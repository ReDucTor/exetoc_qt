// Copyright(C) 1999-2005 LiuTaoTao，bookaa@rorsoft.com


//	exe2c project

//#include "stdafx.h"

#include <cassert>
#include <QString>
#include <cstring>
#include <algorithm>
#include <QDebug>
#include "00000.h"
#include "FileLoad.h"
#include "ApiManage.h"
#include "llvm/Object/COFF.h"

void	Disassembler_Init_offset(const uint8_t * code_buf, ea_t code_offset);
extern std::string DLLDEF_Get_ApiName_from_ord(const char *pDLLname, uint16_t ord);
uint8_t *	ea2ptr(ea_t pos);
ea_t ptr2ea(void* p);
uint8_t	Peek_B(ea_t pos);
uint16_t	Peek_W(ea_t pos);
uint32_t	Peek_D(ea_t pos);

//#include "Deasm_Init.h"

static bool	PELoad_isMFC = false;

bool FileLoader::LoadPE()
{
    const llvm::object::coff_file_header * coffHeader;
    if (llvm::error_code EC = m_binary->getCOFFHeader(coffHeader))
    {
        alert_prtf("Failed to get COFF header: %s\n", EC.message().c_str());
        return false;
    }

    if (coffHeader->Characteristics &
        llvm::COFF::Characteristics::IMAGE_FILE_DLL)
    {
        g_EXEType = enum_PE_dll;
    }

    const llvm::object::pe32_header * peHeader;
    if (llvm::error_code EC = m_binary->getPE32Header(peHeader))
    {
        alert_prtf("Failed to get PE header: %s\n", EC.message().c_str());
        return false;
    }

    switch(peHeader->Subsystem)
    {
    case llvm::COFF::WindowsSubsystem::IMAGE_SUBSYSTEM_NATIVE:
        g_EXEType = enum_PE_sys;
        break;
    case llvm::COFF::WindowsSubsystem::IMAGE_SUBSYSTEM_WINDOWS_GUI:
    case llvm::COFF::WindowsSubsystem::IMAGE_SUBSYSTEM_WINDOWS_CUI:
        g_EXEType = enum_PE_exe;
        break;
    default:
        alert_prtf("Invalid subsystem = %x\n", peHeader->Subsystem);
        assert(0);
        return false;
    }

    uint8_t * p0 = new uint8_t[peHeader->SizeOfImage];
    if (!p0)
    {
        alert_prtf("Unable to allocate space for image");
        return false;
    }

    // NOTE: -4 as coffHeader is missing "PE\0\0"
    memcpy(p0, (uint8_t*)(coffHeader) - 4, peHeader->SizeOfHeaders);

    for (const llvm::object::SectionRef &sec : m_binary->sections())
    {
        const llvm::object::coff_section *section = m_binary->getCOFFSection(sec);
        memcpy(p0 + section->VirtualAddress,
            m_binary->getData().data() + section->PointerToRawData,
            section->SizeOfRawData);
    }

    this->entry_buf = p0 + peHeader->AddressOfEntryPoint;
    this->entry_offset = peHeader->AddressOfEntryPoint + peHeader->ImageBase;

    // Because the file was relocate to address different virtual addresses, so remember this difference
    // Afterwards the main program will use only that offset to access data, regardless of the actual buffer
    // Here because later on  RelocImportTable will use it
    Disassembler_Init_offset(this->entry_buf, this->entry_offset);

    if (!RelocImportTable())
    {
        alert_prtf("Failed RelocImportTable()");
        return false;
    }

    return true;
}
/*
    problems left:
    1.	if the module need a private DLL, then maybe we should change
                    GetModuleHandle
            with
                    LoadLibrary
            and do "FreeLibrary" somewhere
    2.	Only do import with name, should add import with ORD
*/

#include "DLL32DEF.h"

bool FileLoader::RelocImportTable()
{
    const llvm::object::pe32_header * peHeader;
    if (llvm::error_code EC = m_binary->getPE32Header(peHeader))
    {
        alert_prtf("Failed to get PE header: %s\n", EC.message().c_str());
        return false;
    }

    llvm::object::import_directory_iterator iter = m_binary->import_directory_begin();
    llvm::object::import_directory_iterator end = m_binary->import_directory_end();
    for (; iter != end; ++iter)
    {
        const llvm::object::import_directory_table_entry *dir;
        if (iter->getImportTableEntry(dir))
            return false;

        // TODO: LLVM import directory iterators are broken
        // http://llvm.org/bugs/show_bug.cgi?id=19849
        if (!dir->ImportAddressTableRVA)
            break;

        llvm::StringRef dllName;
        if (iter->getName(dllName))
        {
            alert_prtf("Failed to get DLL name");
            return false;
        }
        const char * pDLLname = dllName.data();

        const llvm::object::import_lookup_table_entry32 *importLookupEntry;
        if (iter->getImportLookupEntry(importLookupEntry))
            return false;

        uint32_t * importAddressEntry = (uint32_t*)((this->entry_buf - peHeader->AddressOfEntryPoint) + 
                static_cast<uint32_t>(dir->ImportAddressTableRVA));

        for (; importLookupEntry->data; ++importLookupEntry, ++importAddressEntry) 
        {
            static uint32_t ggdd = 0xACBC0000;
            uint32_t apiaddr = ggdd++;

            std::string apiname;
            if (importLookupEntry->isOrdinal())
            {
                //Input by ord
                apiname = DLLDEF_Get_ApiName_from_ord(pDLLname,
                       static_cast<uint16_t>(importLookupEntry->getOrdinal()));
                if (apiname.size() == 0)
                {
                    QString bufname;
                    bufname = QString("ord_%1_%2").arg((uint16_t)importLookupEntry->getOrdinal(),16).arg(pDLLname);
                    bufname.replace(".","_");
                    apiname = bufname.toStdString();
                }
            }
            else
            {
                uint16_t hint;
                llvm::StringRef name;
                if (m_binary->getHintName(importLookupEntry->getHintNameRVA(), hint, name))
                {
                    return false;
                }
                apiname = name.data();
            }

            *importAddressEntry = apiaddr;

            ApiManage::get()->New_ImportAPI(apiname, ptr2ea(importAddressEntry));
        }
    }

    return true;
}

#define KSPE_IMAGE_SIZEOF_BASE_RELOCATION          8    // Because exclude the first TypeOffset

typedef struct _KSPE_IMAGE_BASE_RELOCATION {
    uint32_t   VirtualAddress;
    uint32_t   SizeOfBlock;
    uint16_t   TypeOffset[1];
} KSPE_IMAGE_BASE_RELOCATION, *PKSPE_IMAGE_BASE_RELOCATION;

#define KSPE_IMAGE_REL_BASED_ABSOLUTE              0
#define KSPE_IMAGE_REL_BASED_HIGH                  1
#define KSPE_IMAGE_REL_BASED_LOW                   2
#define KSPE_IMAGE_REL_BASED_HIGHLOW               3
#define KSPE_IMAGE_REL_BASED_HIGHADJ               4
#define KSPE_IMAGE_REL_BASED_MIPS_JMPADDR          5




ea_t	Find_Main(ea_t start)
{
    ea_t p = start;
    if (Peek_W(p) == 0x8B55
            && Peek_W(p+3) == 0xFF6A
            && Peek_W(p+0x1d) == 0xEC83
            && Peek_B(p+0xaf) == 0xE8		//	401780 - 4016d1 = af
            )
    {
        p += 0xaf;
        uint32_t d = Peek_D(p+1);
        //alert_prtf("p = %x, d = %x",p,d);
        //alert_prtf(" I get main = %x",p+5+d);
        return p+5+d;
    }
    if (Peek_W(p) == 0x8B55
            && Peek_W(p+3) == 0xFF6A
            && Peek_W(p+0x1d) == 0xEC83
            && Peek_B(p+0xc9) == 0xE8		//	00401149 - 00401080 = c9
            )
    {
        p += 0xc9;
        uint32_t d = Peek_D(p+1);
        //alert_prtf("p = %x, d = %x",p,d);
        //alert_prtf(" I get main = %x",p+5+d);
        return p+5+d;
    }

    if (Peek_W(p) == 0xa164
            && Peek_W(p+0x16) == 0x8964
            && Peek_W(p+0x2f) == 0x15ff
            && Peek_B(p+0x152) == 0xE8		//	1A42 - 18f0=152
            )
    {
        p += 0x152;
        uint32_t d = Peek_D(p+1);
        //alert_prtf("p = %x, d = %x",p,d);
        //alert_prtf(" I get main = %x",p+5+d);
        return p+5+d;   //This is the WinMain
    }
    return start;
}

ea_t	Find_WinMain(ea_t start)
{
    ea_t p = start;
    if (Peek_W(p) == 0x8B55
            && Peek_W(p+3) == 0xFF6A
            && Peek_W(p+0x1d) == 0xEC83
            && Peek_B(p+0xc9) == 0xE8
            )
    {
        p += 0xc9;
        uint32_t d = Peek_D(p+1);
        //alert_prtf("p = %x, d = %x",p,d);
        //alert_prtf(" I get WinMain = %x",p+5+d);
        log_prtl(" I get WinMain = %x",p+5+d);
        return p+5+d;
    }
    if (Peek_W(p) == 0x8B55
            && Peek_W(p+3) == 0xFF6A
            && Peek_W(p+0x1d) == 0xEC83
            && Peek_B(p+0x12f) == 0xE8
            )	//	This seems to be used by MFC
    {
        p += 0x12f;
        uint32_t d = Peek_D(p+1);
        //alert_prtf("p = %x, d = %x",p,d);
        //alert_prtf(" I get main = %x",p+5+d);
        log_prtl(" I get MFC WinMain = %x",p+5+d);
        PELoad_isMFC = true;
        return p+5+d;
    }
    //alert_prtf("not find WinMain");
    log_prtl("not find WinMain");
    return start;
}
bool	Valid_ea(ea_t ea)
{
    if (ea >= 0x400000 && ea < 0x80000000)
        return true;
    return false;
}
void OneItem_Init(ea_t ea);
void	SomeOther_about_MFC_load()
{
    if (! PELoad_isMFC)
        return;
    ea_t start = g_FileLoader->entry_offset;

    uint8_t * p = ea2ptr(start);

    p += 0xbb;
    if (p[0] != 0x68 || p[5] != 0x68 || p[10] != 0xe8)
        return;		//	Here are two push immed

    ea_t s_init = *(uint32_t *)(p+6);
    ea_t e_init = *(uint32_t *)(p+1);

    p = ea2ptr(s_init);

    ea_t ea = *(uint32_t *)(p+4);
    if ( ! Valid_ea(ea))
        return;

    ea = *(uint32_t *)(p+8);
    if ( ! Valid_ea(ea))
        return;

    OneItem_Init(ea);

    //alert_prtf("here init start = %x, end = %x, useful = %x",s_init, e_init, ea);
}

void	WinApp_vftbl(ea_t vftbl);

void OneItem_Init(ea_t ea)
{
    uint8_t * p = ea2ptr(ea);
    if (*p != 0xe8)
        return;

    p += *(uint32_t *)(p+1);
    p += 5;

    if (p[0] != 0xb9 || p[5] != 0xe9)
        return;

    //ea_t theapp = *(uint32_t *)(p+1);

    //alert_prtf("theapp = %x",theapp);

    p += *(uint32_t *)(p+6);
    p += 10;

    if (p[5] != 0xe8)
        return;
    if (*(uint16_t*)(p+10) != 0x06c7)
        return;

    ea_t vftbl = *(uint32_t *)(p+12);

    //alert_prtf("vftbl = %x",vftbl);

    WinApp_vftbl(vftbl);
}

#define	WinApp_InitInstance	0x16

void	WinApp_vftbl(ea_t vftbl)
{
    alert_prtf("vftbl = %x",vftbl);
    uint32_t* p = (uint32_t*)ea2ptr(vftbl);

    ea_t ea_InitInstance = p[WinApp_InitInstance];
    alert_prtf("ea_InitInstance = %x",ea_InitInstance);
}
