///////////////////////////////////////////////////////////////
//
// exe2c.h
// Copyright(C) 1999-2005 LiuTaoTao，bookaa@rorsoft.com
// Created at 2005.2.1
// Description:	The interface description of the component
// History:
//
///////////////////////////////////////////////////////////////
//#include "..\..\exe2c\exe2c.H"

#ifndef	_EXE2C_H_
#define	_EXE2C_H_
#include <list>
#include <string>
//#include <Windows.h>
//#include "..\I_KSUNKNOWN\KsFrame.h"

#define	IID_EXE2C				0x00006efa
#define	EXE2C_INITORDER		0x80000000
#define	EXE2C_PARENT_IID		NULL
#define	EXE2C_PRIORITY			0x80000000
class CFunc;
typedef std::list<CFunc *> FUNC_LIST;
typedef unsigned int uint;
struct st_FuncInfo
{
    char name[256];
    int nStep;
    uint headoff;
    uint endoff;
    int stack_purge;
    int m_EBP_base;
    int m_args;
};

struct st_LINE_SYNTAX
{
    //with 0 starting position in the string can not be greater than the string length
    int pos;
    int len;
    int colorindex; // displayed color
    void* handle;   // This is something, for something unknown, or nonsense, this is zero
};

class I_E2COUT
{
public:
    virtual void prt_log(const char * str) = 0;
};

class I_XmlOut;


class I_EXE2C
{
public:
	//Add interface here
	virtual bool	test() = 0;	//Test interface

    virtual void exe2c_main(const std::string &fname) = 0;
    virtual void  prtout_asm(I_XmlOut* iOut) = 0;
    virtual void  prtout_itn(I_XmlOut* iOut) = 0;
    virtual void  prtout_cpp(I_XmlOut* iOut) = 0;
    virtual void  Init(I_E2COUT* i_E2COut) = 0;

    virtual FUNC_LIST::iterator  GetFirstFuncHandle() = 0;
    virtual void    GetFuncInfo(FUNC_LIST::iterator h, st_FuncInfo* info) = 0;
    virtual FUNC_LIST::iterator  GetNextFuncHandle(FUNC_LIST::iterator h) = 0;
    virtual FUNC_LIST::iterator  GetCurFuncHandle() = 0;
    virtual size_t  GetFuncCount() const =0;
    virtual bool    is_valid_function_handle(const FUNC_LIST::iterator &) const=0;
    virtual void  SetCurFunc_by_Name(const char * funcname) = 0;

    virtual bool  analysis_Once()  = 0;
    virtual void  analysis_All()  = 0;
    virtual bool  RenameCurFuncName(const char * name) = 0;
    virtual void  DoCommandLine(const char * cmd) = 0;

    virtual bool  Rename(int xmltype, void * p, const char * newname) = 0; //enum XMLTYPE
    virtual void  ReType(int colorindex, void* handle, const char * newtype) = 0;
    virtual void  Change_Array(int colorindex, void* handle, int newarray) = 0;
    virtual void  HotKey(int colorindex, void* handle, char key) = 0;
    virtual void  LineHotKey(void* hline, char nChar) = 0;
    //Add interface here
};


#endif	// _EXE2C_H_

/*
    Put detailed explanation of interface function here.
*/
