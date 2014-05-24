// Copyright(C) 1999-2005 LiuTaoTao，bookaa@rorsoft.com

//#include "stdafx.h"
#include	"CISC.h"

intptr_t	g_ea2ptr = 0;
// Because the file transferred to a different address and virtual address, so remember this difference
// Afterward the main program uses only the offset to access, regardless of the actual buffer
void	Disassembler_Init_offset(const uint8_t * code_buf, ea_t code_offset)
{
    g_ea2ptr = (intptr_t)code_buf - code_offset;
}

uint8_t *ea2ptr(ea_t pos)
{
    return (uint8_t *)(g_ea2ptr+pos);
}
ea_t ptr2ea(void* p)
{
    uint8_t * p1 = ea2ptr(0);
    return (uint8_t *)p - p1;
}

uint8_t Peek_B(ea_t pos)
{
    uint8_t * p = ea2ptr(pos);
    return *p;
}
uint16_t Peek_W(ea_t pos)
{
    uint8_t * p = ea2ptr(pos);
    return *(uint16_t *)p;
}
uint32_t	Peek_D(ea_t pos)
{
    uint8_t * p = ea2ptr(pos);
    return *(uint32_t *)p;
}
bool XCPUCODE::IsCalculatedJmp() const
{
    if (opcode != C_JMP)
            return false;
    if(op[0].mode == OP_Register) // jmp eax / jmp ebx
        return true;

    if (op[0].mode == OP_Address) // jmp [Offset+RegBase +Scale*RegIndex]
        return true;
    return false;

}
bool XCPUCODE::IsJmpMemIndexed() const
{
    if (opcode != C_JMP)
            return false;
    if (op[0].mode != OP_Address)
        return false;
    if (op[0].addr.base_reg_index != _NOREG_)
        return false;
    if (op[0].addr.off_reg_index == _NOREG_)
        return false;
    if (op[0].addr.off_reg_scale != 4)
        return false;
    return true;

}
bool	XCPUCODE::IsJxx() const
{
    uint8_t opcode = this->opcode;
    switch (opcode)
    {
    case	C_JO:
    case	C_JNO:
    case	C_JB:
    case	C_JNB:
    case	C_JZ:
    case	C_JNZ:
    case	C_JNA:
    case	C_JA:
    case	C_JS:
    case	C_JNS:
    case	C_JP:
    case	C_JNP:
    case	C_JL:
    case	C_JNL:
    case	C_JLE:
    case	C_JNLE:

    case	C_JCASE:
        return true;

    default:
        return false;
    }
}
bool	XCPUCODE::IsJmpNear() const
{
    if (this->opcode == C_JMP && this->op[0].mode == OP_Near)
        return true;
    return false;
}
bool XCPUCODE::IsCallNear() const
{
    return (this->opcode == C_CALL) && (this->op[0].mode == OP_Near);
}

bool OPERITEM::isRegOp(uint32_t reg_idx)
{
    return (mode==OP_Register)&&(getReg()==reg_idx);
}
bool OPERITEM::isStaticOffset() //! return true if this is OP_Address and it does not depend on other regs e.x. [0x11212]
{
    return (mode == OP_Address) && (addr.base_reg_index == _NOREG_) && (addr.off_reg_index == _NOREG_);
}
OPERITEM OPERITEM::createReg(int reg_idx,int width)
{
    OPERITEM result;
    ((llvm::MCOperand &)result) = llvm::MCOperand::CreateReg(reg_idx);
    result.mode=OP_Register;
    result.opersize=width;
    return result;
}


// To make a disassembly, pos auto-increment, the results remain xcpu
uint8_t	 Disasm::Disasm_OneCode(ea_t pos)
{
    st_IDA_OUT idaout;
    uint32_t n = this->Disassembler_X(ea2ptr(pos), pos, &idaout);
    return (uint8_t)n;
}
