// Copyright(C) 1999-2005 LiuTaoTao，bookaa@rorsoft.com


//	exe2c project

////#include "stdafx.h"
#include <stdint.h>
#include "00000.h"
#include "FileLoad.h"

#include <llvm/Object/COFF.h>

//#define	SEG0	0x1000
//static const int Load_Resources=0;
//static const int Load_Debug=0;
//static const int Load_Data=1;


FileLoader* g_FileLoader = NULL;

FileLoader::FileLoader(void)
{
    exetype=UNKNOWN_EXE;
    fbuff=NULL;
    g_EXEType = (enum_EXEType)0;
    g_FileLoader=this;
}

FileLoader::~FileLoader(void)
{
}

bool	FileLoader::if_valid_ea(ea_t ea)
{
    //FIXME: this should check the actual image for extents.
    switch (g_EXEType)
    {
        case enum_PE_sys:
            return true;
        case enum_PE_exe:
            if (ea < 0x400000)
                return false;
            return true;
    }
    return true;
}

//checks header info, puts up initial loading dialog box and
//selects info routine for file.
bool FileLoader::load(const char * fname)
{
    llvm::ErrorOr<llvm::object::Binary *> BinaryOrErr = llvm::object::createBinary(fname);
    if (llvm::error_code EC = BinaryOrErr.getError())
    {
        alert_prtf("Failed to load file: %s", EC.message().c_str());
        return false;
    }

    std::unique_ptr<llvm::object::Binary> binary(BinaryOrErr.get());

    llvm::object::COFFObjectFile * obj = llvm::dyn_cast<llvm::object::COFFObjectFile>(binary.get());

    if (!obj)
    {
        alert_prtf("%s is not a COFF object file", fname);
        return false;
    }

    m_binary.reset(obj);

    // TODO: Verify exetype == PE_EXE
    exetype = PE_EXE;

    fbuff = (uint8_t*)m_binary->getData().data();

    uint32_t pe_offset = *(uint32_t *)(fbuff+0x3c);

    return LoadPE(pe_offset);
}
bool	IfInWorkSpace(ea_t off)
{	//	check if off lie in our work space
    //Do something about it later, for the time being simple check
    if (off > 0x400000 && off < 0x600000)
        return true;
    return false;
}
