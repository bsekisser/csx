#include "csx.h"
#include "csx_core.h"

#include "csx_core_thumb_inst.h"

/* **** */

static void csx_core_thumb_disasm(csx_core_p core, uint32_t address, uint32_t opcode)
{
	csx_core_disasm(core, address | 1, opcode);
}

/* **** */

static void csx_core_thumb_add_sub_i3_rn_rd(csx_core_p core, uint16_t opcode)
{
	int cce = 1;

	uint8_t op2 = opcode & _BV(9);
	uint8_t imm3 = _bits(opcode, 8, 6);
	uint8_t rn = _bits(opcode, 5, 3);
	uint32_t rn_v = csx_reg_get(core, rn);
	uint8_t rd = _bits(opcode, 2, 0);
	
	uint32_t rd_v = rn_v;
	
	if(op2)
	{
		rd_v -= imm3;
		CORE_TRACE("subs(rd(%u), rn(%u), 0x%02x); /* 0x%08x - 0x%02x = 0x%08x */",
			rd, rn, imm3, rn_v, imm3, rd_v);
	}
	else
	{
		rd_v += imm3;
		CORE_TRACE("adds(rd(%u), rn(%u), 0x%02x); /* 0x%08x + 0x%02x = 0x%08x */",
			rd, rn, imm3, rn_v, imm3, rd_v);
	}

	csx_reg_set(core, rd, rd_v);
	csx_core_flags_nzcv(core, rd_v, rn_v, imm3);
}

static void csx_core_thumb_b(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
	uint16_t opcode1 = opcode & _BF(15, 11);
	
	switch(opcode1)
	{
		case	0xf000:
		{
			uint32_t pc = csx_reg_get(core, rPC);
			uint32_t eao = _bits_sext(opcode, 10, 0) << 12;
			uint32_t lr = pc + eao;
			CORE_TRACE("bh(0x%08x); /* 0x%08x + 0x%08x */", lr, pc, eao);
			csx_reg_set(core, rLR, lr);
		}	break;
		case	0xf800:
		{
			uint32_t lr = csx_reg_get(core, rLR);
			uint32_t eao = _bits(opcode, 10, 0) << 1;
			uint32_t new_pc = lr + eao;
			uint32_t new_lr = new_pc + 2;
			CORE_TRACE("bl(0x%08x); /* 0x%08x + 0x%08x, LR = 0x%08x */", new_pc, lr, eao, new_lr);
			csx_reg_set(core, rPC, new_pc);
			csx_reg_set(core, rLR, new_lr | 1);
		}	break;
		default:
			TRACE("ir = 0x%04x, opcode = 0x%04x", opcode, opcode1);
			LOG_ACTION(exit(1));
			break;
	}
}

static void csx_core_thumb_bxx(csx_core_p core, uint16_t opcode)
{
	uint8_t cond = _bits(opcode, 11, 8);
	uint8_t cce = csx_core_check_cc(core, opcode, cond);
	uint32_t imm8 = _bits_sext(opcode, 7, 0) << 1;

	uint32_t pc = csx_reg_get(core, rPC);
	uint32_t new_pc = pc + imm8;

	CORE_TRACE("b(0x%08x); /* 0x%08x + 0x%03x */", new_pc, pc, imm8);

	if(cce)
		csx_reg_set(core, rPC, new_pc);
}

static void csx_core_thumb_ldr_rd_i(csx_core_p core, uint16_t opcode)
{
	core->ccs = "EA";
	int cce = 1;

	uint8_t rd = _bits(opcode, 10, 8);
	uint8_t imm8 = _bits(opcode, 7, 0) << 2;

	uint32_t ea = (csx_reg_get(core, rPC) & ~0x03) + imm8;
	uint32_t rd_v = core->csx->mmu.read(core->csx, ea, sizeof(uint32_t));

	CORE_TRACE("ldr(r(%u), rPC[0x%02x]); /* [0x%08x](0x%08x) */",
		rd, imm8, ea, rd_v);

	csx_reg_set(core, rd, rd_v);
}

static void csx_core_thumb_ldst_bwh_o_rn_rd(csx_core_p core, uint16_t opcode)
{
	csx_p csx = core->csx;
	int cce = 1;
	
//	struct {
		uint8_t b = BIT_OF(opcode, 12);
		uint8_t l = BIT_OF(opcode, 11);
//	}bit;
	
	uint8_t	offset = _bits(opcode, 10, 6);
	uint8_t rn = _bits(opcode, 5, 3);
	uint32_t rn_v = csx_reg_get(core, rn);
	uint8_t rd = _bits(opcode, 2, 0);
	
	const char *ss = "";
	uint8_t size = 0;
	
	if(CSX_CORE_THUMB_LDST_BW_O_RN_RD == (opcode & CSX_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
	{
		if(/*bit.*/b)
		{
			ss = "b";
			size = 8;
		}
		else
		{
			offset <<= 4;
			size = 32;
		}
	}
	else
	{
		ss = "h";
		offset <<= 2;
		size = 16;
	}
	
	uint32_t ea = rn_v + offset;

	uint32_t rd_v;
	if(/*bit.*/l)
		rd_v = core->csx->mmu.read(csx, ea, size);
	else
		rd_v = csx_reg_get(core, rd);
		
	CORE_TRACE("%sr%s(rd(%u), rn(%u)[0x%03x]); /* [(0x%08x + 0x%03x) = 0x%08x](0x%08x) */",
		/*bit.*/l ? "ld" : "st", ss, rd, rn, offset, rn_v, offset, ea, rd_v);
	
	if(/*bit.*/l)
		csx_reg_set(core, rd, rd_v);
	else
		core->csx->mmu.write(csx, ea, rd_v, size);
}

static void csx_core_thumb_ldstm_rn_rxx(csx_core_p core, uint16_t opcode)
{
	csx_p csx = core->csx;
	int cce = 1;

//	struct {
		uint8_t l = BIT_OF(opcode, 11);
//	}bit;

	uint8_t rn = _bits(opcode, 10, 8);
	uint32_t rn_v = csx_reg_get(core, rn);
	uint8_t rlist = _bits(opcode, 7, 0);
	
	char	tout[256], *dst = tout, *end = &tout[255];

	uint32_t ea = rn_v;
	
	for(int i = 0; i < 8; i++)
	{
		if(BIT_OF(rlist, i))
		{
			uint32_t rxx_v;

			if(/*bit.*/l)
			{
				rxx_v = csx->mmu.read(csx, ea, sizeof(uint32_t));
				csx_reg_set(core, i, rxx_v);
			}
			else
			{	
				rxx_v = csx_reg_get(core, i);
				csx->mmu.write(csx, ea, rxx_v, sizeof(uint32_t));
			}
			ea += 4;
		}
	}
	csx_reg_set(core, rn, ea);
	
	dst += snprintf(dst, end - dst, "%sm(rn(%u)++, r{0b", /*bit.*/l ? "ld" : "st", rn);
	for(int i = 0; i < 8; i++)
	{
		uint8_t rxx = BIT_OF(rlist, (7 - i));
		dst += snprintf(dst, end - dst, "%01u", rxx);
	}

	CORE_TRACE("%s});", tout);

}

static void csx_core_thumb_lsr_imm5_rm_rd(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
	uint8_t imm5 = _bits(opcode, 10, 6);
	uint8_t rm = _bits(opcode, 5, 3);
	uint32_t rm_v = csx_reg_get(core, rm);
	uint8_t rd = _bits(opcode, 2, 0);
	
	uint8_t shift = imm5;
	if(0 == imm5)
		shift = 32;

	CPSR &= ~CSX_PSR_C;
	CPSR |= BIT2BIT(rm_v, (shift - 1), CSX_PSR_BIT_C);

	uint32_t rd_v = rm_v >> shift;
	
	csx_core_flags_nz(core, rd_v);
	
	CORE_TRACE("lsr(rd(%u), rm(%u), 0x%02x); /* 0x%08x >> 0x%02x = 0x%08x */",
		rd, rm, shift, rm_v, shift, rd_v);
	
	if(1) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & CSX_PSR_N), !!(CPSR & CSX_PSR_Z),
		!!(CPSR & CSX_PSR_C), !!(CPSR & CSX_PSR_V));

	csx_reg_set(core, rd, rd_v);
}


/* **** */

void csx_core_thumb_step(csx_core_p core)
{
	csx_p csx = core->csx;
	
	uint32_t pc = csx_reg_get(core, INSN_PC);
	csx->cycle++;

	csx_reg_set(core, rPC, pc + 2);

	uint32_t ir = csx->mmu.read(csx, pc, sizeof(uint16_t));


	for(uint8_t lsb = 8; lsb < 13; lsb++)
	{
		uint32_t opcode = ir & _BF(15, lsb);

		switch(opcode)
		{
		/* **** */
			case	0x0800:
				if(CSX_CORE_THUMB_LSR_IMM5_RM_RD == (ir & CSX_CORE_THUMB_LSR_IMM5_RM_RD_MASK))
					return(csx_core_thumb_lsr_imm5_rm_rd(core, ir));
				break;
			case	0x1800:
				if(CSX_CORE_THUMB_ADD_SUB_I3_RN_RD == (ir & CSX_CORE_THUMB_ADD_SUB_I3_RN_RD_MASK))
					return(csx_core_thumb_add_sub_i3_rn_rd(core, ir));
				break;
			case	0x4800:
				if(CSX_CORE_THUMB_LDR_RD_I == (ir & CSX_CORE_THUMB_LDR_RD_I_MASK))
					return(csx_core_thumb_ldr_rd_i(core, ir));
				break;
			case	0x6000:
				if(CSX_CORE_THUMB_LDST_BW_O_RN_RD == (ir & CSX_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
					return(csx_core_thumb_ldst_bwh_o_rn_rd(core, ir));
				break;
			case	0x8000:
				if(CSX_CORE_THUMB_LDST_H_O_RN_RD == (ir & CSX_CORE_THUMB_LDST_H_O_RN_RD_MASK))
					return(csx_core_thumb_ldst_bwh_o_rn_rd(core, ir));
				break;
			case	0xc000:
				if(CSX_CORE_THUMB_LDSTM_RN_RXX == (ir & CSX_CORE_THUMB_LDSTM_RN_RXX_MASK))
					return(csx_core_thumb_ldstm_rn_rxx(core, ir));
				break;
			case	0xd000:
				opcode = ir & _BF(15, 8);
				switch(opcode)
				{
					case	0xde00: /* undefined */
					case	0xdf00: /* swi */
//						TRACE("ir = 0x%04x, opcode = 0x%04x, lsb", ir, opcode);
						break;
					default:
						return(csx_core_thumb_bxx(core, ir));
						break;
				}
			case	0xe000:
			case	0xf000:
				return(csx_core_thumb_b(core, ir));
				break;
		/* **** */
		}
//		TRACE("ir = 0x%04x, opcode = 0x%04x, lsb = 0x%02x", ir, opcode, lsb);
	}//while(lsb-- > 8);

	csx_core_thumb_disasm(core, pc, ir);
	LOG_ACTION(exit(1));
}
