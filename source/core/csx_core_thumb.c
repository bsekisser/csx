#include <assert.h>

#include "csx.h"
#include "csx_core.h"

#include "csx_core_thumb_inst.h"

/* **** */

static void csx_core_thumb_disasm(csx_core_p core, uint32_t address, uint32_t opcode)
{
	csx_core_disasm(core, address | 1, opcode);
}

/* **** */

static void csx_core_thumb_add_sub_rn_rd(csx_core_p core, uint16_t opcode)
{
	int cce = 1;

	uint8_t bit_i = BEXT(opcode, 10);
	uint8_t op2 = BEXT(opcode, 9);

	uint8_t rm = BFEXT(opcode, 8, 6);
	uint32_t rm_v = rm;
	if(!bit_i)
		rm_v = csx_reg_get(core, rm);
	
	uint8_t rn = BFEXT(opcode, 5, 3);
	uint32_t rn_v = csx_reg_get(core, rn);
	uint8_t rd = BFEXT(opcode, 2, 0);
	
	uint32_t rd_v = rn_v;
	
	if(op2)
	{
		rd_v -= rm_v;
		if(bit_i)
		{
			CORE_TRACE("subs(%s, %s, 0x%01x); /* 0x%08x - 0x%01x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rn), rm_v, rn_v, rm_v, rd_v);
		}
		else
		{
			CORE_TRACE("subs(%s, %s, %s); /* 0x%08x - 0x%08x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rn), _arm_reg_name(rm), rn_v, rm_v, rd_v);
		}
	}
	else
	{
		rd_v += rm_v;
		if(bit_i)
		{
			CORE_TRACE("adds(%s, %s, 0x%01x); /* 0x%08x + 0x%01x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rn), rm_v, rn_v, rm_v, rd_v);
		}
		else
		{
			CORE_TRACE("adds(%s, %s, %s); /* 0x%08x + 0x%08x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rn), _arm_reg_name(rm), rn_v, rm_v, rd_v);
		}
	}

	csx_reg_set(core, rd, rd_v);
	csx_core_flags_nzcv(core, rd_v, rn_v, rm_v);
}

static void csx_core_thumb_add_sub_sp_i7(csx_core_p core, uint16_t opcode)
{
	int cce = 1;

	int sub = BEXT(opcode, 7);
	uint16_t imm7 = BFEXT(opcode, 6, 0) << 2;

	uint32_t sp_v = csx_reg_get(core, rSP);
	uint32_t res = sp_v;
	
	if(sub)
	{
		res -= imm7;
		CORE_TRACE("sub(rSP, 0x%04x); /* 0x%08x - 0x%04x = 0x%08x */",
			imm7, sp_v, imm7, res);
	}
	else
	{
		res += imm7;
		CORE_TRACE("add(rSP, 0x%04x); /* 0x%08x + 0x%04x = 0x%08x */",
			imm7, sp_v, imm7, res);
	}

	csx_reg_set(core, rSP, res);
}

static void csx_core_thumb_ascm_rd_i(csx_core_p core, uint16_t opcode)
{
	int cce = 1, wb = 1;
	
	uint8_t operation = BFEXT(opcode, 12, 11);
	uint8_t rd = BFEXT(opcode, 10, 8);
	uint32_t rd_v = csx_reg_get(core, rd);
	uint8_t imm8 = BFEXT(opcode, 7, 0);
	
	uint32_t res = rd_v;
	
	switch(operation)
	{
		case THUMB_ASCM_OP_ADD:
			res += imm8;
			CORE_TRACE("adds(%s, 0x%03x); /* 0x%08x + 0x%03x = 0x%08x */",
				_arm_reg_name(rd), imm8, rd_v, imm8, res);
			csx_core_flags_nzcv(core, res, rd_v, imm8);
			break;
		case THUMB_ASCM_OP_CMP:
			wb = 0;
			res -= imm8;
			CORE_TRACE("cmp(%s, 0x%03x); /* 0x%08x - 0x%03x = 0x%08x */",
				_arm_reg_name(rd), imm8, rd_v, imm8, res);
			csx_core_flags_nzcv(core, res, rd_v, imm8);
			break;
		case THUMB_ASCM_OP_MOV:
			res = imm8;
			CORE_TRACE("mov(%s, 0x%03x);", _arm_reg_name(rd), imm8);
			csx_core_flags_nz(core, res);
			break;
		case THUMB_ASCM_OP_SUB:
			res -= imm8;
			CORE_TRACE("subs(%s, 0x%03x); /* 0x%08x - 0x%03x = 0x%08x */",
				_arm_reg_name(rd), imm8, rd_v, imm8, res);
			csx_core_flags_nzcv(core, res, rd_v, imm8);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			csx_core_thumb_disasm(core, csx_reg_get(core, TEST_PC), opcode);
			LOG_ACTION(exit(1));
	}
	
	if(wb)
		csx_reg_set(core, rd, res);
}

static void csx_core_thumb_b(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
	uint16_t opcode1 = opcode & _BF(15, 11);
	int bit_blx = BEXT(opcode, 12);

	switch(opcode1)
	{
		case	0xf000:
		{
			uint32_t pc = csx_reg_get(core, rPC);
			uint32_t eao = _bits_sext(opcode, 10, 0) << 12;
			uint32_t lr = pc + eao;
			CORE_TRACE("add(rLR, rPC, LSL(0x%04x, 12)) /* LR = 0x%08x (PC = 0x%08x + 0x%08x) */",
				eao >> 12, lr & ~1, pc, eao);
			csx_reg_set(core, rLR, lr);
		}	break;
		case	0xe800:
		case	0xf800:
		{
			uint32_t pc = csx_reg_get(core, TEST_PC);
			uint32_t lr = csx_reg_get(core, rLR);
			uint32_t eao = BFMOV(opcode, 10, 0, 1);
			uint32_t new_pc = lr + eao;
			uint32_t new_lr = pc;
			CORE_TRACE("bl%s(0x%08x); /* 0x%08x + 0x%04x, LR = 0x%08x */",
				bit_blx ? "" : "x", new_pc & ~1, lr & ~1, eao, new_lr);
			if(bit_blx)
				csx_reg_set(core, rPC, new_pc);
			else
				csx_reg_set(core, INSN_PC, (new_pc & ~3));
			csx_reg_set(core, rLR, new_lr | 1);
		}	break;
		default:
			TRACE("ir = 0x%04x, opcode = 0x%04x", opcode, opcode1);
			LOG_ACTION(exit(1));
			break;
	}
}

static void csx_core_thumb_bx(csx_core_p core, uint16_t opcode)
{
	int cce = 1;

	int tsbz = _check_sbz(opcode, 2, 0, 0, 0);
	if(tsbz)
		LOG_ACTION(exit(1));

	csx_reg_t rm = BFEXT(opcode, 6, 3);
	
	uint32_t new_pc = csx_reg_get(core, rm);

	CORE_TRACE("bx(%s); /* 0x%08x */", _arm_reg_name(rm), new_pc & ~1);

	csx_reg_set(core, INSN_PC, new_pc);
}

static void csx_core_thumb_bxx(csx_core_p core, uint16_t opcode)
{
	uint8_t cond = BFEXT(opcode, 11, 8);
	uint8_t cce = csx_core_check_cc(core, opcode, cond);
	int32_t imm8 = _bits_sext(opcode, 7, 0) << 1;

	uint32_t pc = csx_reg_get(core, rPC);
	uint32_t new_pc = pc + imm8;

	CORE_TRACE("b(0x%08x); /* 0x%08x + 0x%03x */", new_pc & ~1, pc, imm8);

	if(cce)
	{
		core->csx->cycle += 3;
		csx_reg_set(core, rPC, new_pc);
	}
}

static void csx_core_thumb_dp_rms_rdn(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
	uint8_t operation = BFEXT(opcode, 9, 6);

	csx_reg_t rm = BFEXT(opcode, 5, 3);
	uint32_t rm_v = csx_reg_get(core, rm);
	
	csx_reg_t rd = BFEXT(opcode, 2, 0);
	uint32_t rd_v = csx_reg_get(core, rd);
	
	uint32_t res = rd_v;
	
	switch(operation)
	{
		case THUMB_DP_OP_AND:
			res &= rm_v;
			CORE_TRACE("ands(%s, %s); /* 0x%08x & 0x%08x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), rd_v, rm_v, res);
			csx_core_flags_nz(core, res);
			break;
		case THUMB_DP_OP_MVN:
			res = ~rm_v;
			CORE_TRACE("mvns(%s, %s); /* ~0x%08x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), rm_v, res);
			csx_core_flags_nz(core, res);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			csx_core_thumb_disasm(core, core->pc, opcode);
			LOG_ACTION(exit(1));
			break;
	}

	csx_reg_set(core, rd, res);
}

static void csx_core_thumb_ldr_rd_i(csx_core_p core, uint16_t opcode)
{
	core->ccs = "EA";
	int cce = 1;

	uint8_t rd = BFEXT(opcode, 10, 8);
	uint8_t imm8 = BFMOV(opcode, 7, 0, 2);

	uint32_t ea = (csx_reg_get(core, rPC) & ~0x03) + imm8;
	uint32_t rd_v = csx_mmu_read(core->csx->mmu, ea, sizeof(uint32_t));

	CORE_TRACE("ldr(%s, rPC[0x%03x]); /* [0x%08x](0x%08x) */",
		_arm_reg_name(rd), imm8, ea, rd_v);

	csx_reg_set(core, rd, rd_v);
}

static void csx_core_thumb_ldst_bwh_o_rn_rd(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
//	struct {
		uint8_t bit_b = BEXT(opcode, 12);
		uint8_t bit_l = BEXT(opcode, 11);
//	}bit;
	
	uint8_t	offset = BFEXT(opcode, 10, 6);
	uint8_t rn = BFEXT(opcode, 5, 3);
	uint32_t rn_v = csx_reg_get(core, rn);
	uint8_t rd = BFEXT(opcode, 2, 0);
	
	const char *ss = "";
	uint8_t size = 0;
	
	if(CSX_CORE_THUMB_LDST_BW_O_RN_RD == (opcode & CSX_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
	{
		if(bit_b)
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
	if(bit_l)
		rd_v = csx_mmu_read(core->csx->mmu, ea, size);
	else
		rd_v = csx_reg_get(core, rd);
		
	CORE_TRACE("%sr%s(%s, %s[0x%03x]); /* [(0x%08x + 0x%03x) = 0x%08x](0x%08x) */",
		bit_l ? "ld" : "st", ss, _arm_reg_name(rd), _arm_reg_name(rn), offset, rn_v, offset, ea, rd_v);
	
	if(bit_l)
		csx_reg_set(core, rd, rd_v);
	else
		csx_mmu_write(core->csx->mmu, ea, rd_v, size);
}

static void csx_core_thumb_ldst_rm_rn_rd(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
//	struct {
		uint8_t bit_l = BEXT(opcode, 11);
		uint8_t bwh = BFEXT(opcode, 10, 9);
//	}bit;
	
	uint8_t rm = BFEXT(opcode, 8, 6);
	core->csx->cycle++;
	uint32_t rm_v = csx_reg_get(core, rm);
	
	uint8_t rn = BFEXT(opcode, 5, 3);
	uint32_t rn_v = csx_reg_get(core, rn);
	uint8_t rd = BFEXT(opcode, 2, 0);
	
	const char *ss = "";
	uint8_t size = 0;
	
	switch(bwh)
	{
		case 0x00:
			size = 32;
		break;
		case 0x01:
			ss = "h";
			size = 16;
		break;
		case 0x02:
			ss = "b";
			size = 8;
		break;
		default:
			LOG_ACTION(exit(1));
			break;
	}
	
	uint32_t ea = rn_v + rm_v;

	uint32_t rd_v;
	if(bit_l)
		rd_v = csx_mmu_read(core->csx->mmu, ea, size);
	else
		rd_v = csx_reg_get(core, rd);
		
	CORE_TRACE("%sr%s(%s, %s, %s); /* 0x%08x[0x%08x](0x%08x) = 0x%08x */",
		bit_l ? "ld" : "st", ss, _arm_reg_name(rd), _arm_reg_name(rn), _arm_reg_name(rm), rn_v, rm_v, ea, rd_v);
	
	if(bit_l)
		csx_reg_set(core, rd, rd_v);
	else
		csx_mmu_write(core->csx->mmu, ea, rd_v, size);
}

static void csx_core_thumb_ldstm_rn_rxx(csx_core_p core, uint16_t opcode)
{
	csx_p csx = core->csx;
	const int cce = 1;

//	struct {
		const uint8_t bit_l = BEXT(opcode, 11);
//	}bit;

	const uint8_t rn = BFEXT(opcode, 10, 8);
	uint32_t rn_v = csx_reg_get(core, rn);
	const uint8_t rlist = BFEXT(opcode, 7, 0);
	
	char	tout[256], *dst = tout, *end = &tout[255];

	const uint32_t start_address = rn_v;
	const uint32_t end_address = start_address + (__builtin_popcount(rlist) << 2) - 4;
	
	uint32_t ea = rn_v;
	
	for(int i = 0; i <= 7; i++)
	{
		if(BTST(rlist, i))
		{
			uint32_t rxx_v;
			csx->cycle++;

			if(bit_l)
			{
				rxx_v = csx_mmu_read(csx->mmu, ea, sizeof(uint32_t));
				csx_reg_set(core, i, rxx_v);
			}
			else
			{	
				rxx_v = csx_reg_get(core, i);
				csx_mmu_write(csx->mmu, ea, rxx_v, sizeof(uint32_t));
			}
			ea += 4;
		}
	}
	
	assert(end_address == ea - 4);
	
	csx_reg_set(core, rn, ea);
	
	dst += snprintf(dst, end - dst, "%sm(%s++, r{0b", bit_l ? "ld" : "st", _arm_reg_name(rn));
	for(int i = 0; i <= 7; i++)
	{
		uint8_t rxx = BEXT(rlist, (7 - i));
		dst += snprintf(dst, end - dst, "%01u", rxx);
	}

	CORE_TRACE("%s});", tout);
}

static void csx_core_thumb_sbi_imm5_rm_rd(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
	uint8_t operation = BFEXT(opcode, 12, 11);
	uint8_t imm5 = BFEXT(opcode, 10, 6);
	uint8_t rm = BFEXT(opcode, 5, 3);
	uint32_t rm_v = csx_reg_get(core, rm);
	uint8_t rd = BFEXT(opcode, 2, 0);
	
	uint8_t shift = imm5;
	const char *ops = "";
	uint32_t rd_v = 0;
	switch(operation)
	{
		case THUMB_SBI_OP_ASR:
			ops = "asr";
			if(shift)
			{
				BMAS(CPSR, CSX_PSR_BIT_C, BEXT(rm_v, (shift - 1)));
				rd_v = (((signed)rm_v) >> shift);
			}
			else
			{
				int rm31_c = BEXT(rm_v, 31);
				BMAS(CPSR, CSX_PSR_BIT_C, rm31_c);
				rd_v = rm31_c ? -1 : 0;
			}
			break;
		case THUMB_SBI_OP_LSL:
			if(shift)
			{
				BMAS(CPSR, CSX_PSR_BIT_C, BEXT(rm_v, (32 - shift)));
				rd_v = rm_v << shift;
			}
			break;
		case THUMB_SBI_OP_LSR:
			if(!shift)
				shift = 32;
			ops = "lsr";
			BMAS(CPSR, CSX_PSR_BIT_C, BEXT(rm_v, (shift - 1)));
			rd_v = rm_v >> shift;
			break;
		default:
			LOG_ACTION(exit(1));
	}
	
	csx_core_flags_nz(core, rd_v);
	
	if(1) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & CSX_PSR_N), !!(CPSR & CSX_PSR_Z),
		!!(CPSR & CSX_PSR_C), !!(CPSR & CSX_PSR_V));

	CORE_TRACE("%s(%s, %s, 0x%02x); /* %s(0x%08x, 0x%02x) = 0x%08x */",
		ops, _arm_reg_name(rd), _arm_reg_name(rm), shift, ops, rm_v, shift, rd_v);
	
	csx_reg_set(core, rd, rd_v);
}

static void csx_core_thumb_pop_push(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
	csx_p csx = core->csx;
	csx_mmu_p mmu = csx->mmu;
	
//	struct {
		const uint8_t bit_l = BEXT(opcode, 11);
		const uint8_t bit_r = BEXT(opcode, 8);
//	}bit;
	
	const uint8_t rlist = BFEXT(opcode, 7, 0);

	uint32_t sp_v = csx_reg_get(core, rSP);
	
	const uint8_t rcount = bit_r + __builtin_popcount(rlist);

	uint32_t start_address = sp_v, end_address = sp_v;
	
	if(bit_l)
	{ /* pop */
		end_address += (rcount << 2);
	}
	else
	{ /* push */
		start_address -= (rcount << 2);
		end_address -= 4;
	}
	
	uint32_t ea = start_address;
	
	char	tout[256], *dst = tout, *end = &tout[255];

	T(dst += snprintf(dst, end - dst, "%s(rSP, r{0b", bit_l ? "pop" : "push"));

	uint32_t rxx_v;

	for(int i = 0; i <=7; i++)
	{
		T(uint8_t rxx = BEXT(rlist, (7 - i)));
		T(dst += snprintf(dst, end - dst, "%01u", rxx));

		if(BEXT(rlist, i))
		{
			csx->cycle++;
			if(bit_l)
			{ /* pop */
				rxx_v = csx_mmu_read(mmu, ea, sizeof(uint32_t));
				if(0) LOG("ea = 0x%08x, r(%u) = 0x%08x", ea, i, rxx_v);
				csx_reg_set(core, i, rxx_v);
			}
			else
			{ /* push */
				rxx_v = csx_reg_get(core, i);
				if(0) LOG("ea = 0x%08x, r(%u) = 0x%08x", ea, i, rxx_v);
				csx_mmu_write(mmu, ea, rxx_v, sizeof(uint32_t));
			}
			ea += 4;
		}
	}

	T(const char *pclrs = bit_r ? (bit_l ? ", PC" : ", LR") : "");
	
	CORE_TRACE("%s%s});", tout, pclrs);

	if(bit_r)
	{
		if(bit_l)
		{ /* pop */
			rxx_v = csx_mmu_read(mmu, ea, sizeof(uint32_t));
			csx_reg_set(core, INSN_PC, rxx_v);
		}
		else
		{ /* push */
			rxx_v = csx_reg_get(core, rLR);
			csx_mmu_write(mmu, ea, rxx_v, sizeof(uint32_t));
		}
		ea += 4;
	}
	
	if(0) LOG("SP = 0x%08x, PC = 0x%08x", sp_v, csx_reg_get(core, TEST_PC));
	
	if(bit_l)
	{ /* pop */
		assert(end_address == ea);
		csx_reg_set(core, rSP, end_address);
	}
	else
	{ /* push */
		assert(end_address == (ea - 4));
		csx_reg_set(core, rSP, start_address);
	}
}

static void csx_core_thumb_sdp_rms_rdn(csx_core_p core, uint16_t opcode)
{
	int cce = 1;
	
	uint8_t operation = BFEXT(opcode, 9, 8);

	csx_reg_t rm = BFEXT(opcode, 6, 3);
	uint32_t rm_v = csx_reg_get(core, rm);
	csx_reg_t rd = BFEXT(opcode, 2, 0) | BMOV(opcode, 7, 3);
	uint32_t rd_v = csx_reg_get(core, rd);
	
	uint32_t res = rd_v;
	
	switch(operation)
	{
		case THUMB_SDP_OP_MOV:
			res = rm_v;
			CORE_TRACE("mov(%s, %s); /* 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), res);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			csx_core_thumb_disasm(core, core->pc, opcode);
			LOG_ACTION(exit(1));
			break;
	}

	csx_reg_set(core, rd, res);
}

/* **** */

void csx_core_thumb_step(csx_core_p core)
{
	core->ccs = "AL";

	uint32_t pc;
	uint32_t ir = csx_reg_pc_fetch_step(core, 2, &pc);

	core->csx->cycle++;

	uint8_t lsb;
	uint32_t opcode;
	
	for(lsb = 8; lsb <= 13; lsb++)
	{
		opcode = ir & _BF(15, lsb);

		switch(opcode)
		{
		/* **** */
			case	0x0000:
				if(CSX_CORE_THUMB_SBI_IMM5_RM_RD == (ir & CSX_CORE_THUMB_SBI_IMM5_RM_RD_MASK))
					return(csx_core_thumb_sbi_imm5_rm_rd(core, ir));
				break;
			case	0x1800:
				if(CSX_CORE_THUMB_ADD_SUB_RN_RD == (ir & CSX_CORE_THUMB_ADD_SUB_RN_RD_MASK))
					return(csx_core_thumb_add_sub_rn_rd(core, ir));
				break;
			case	0x2000:
				if(CSX_CORE_THUMB_ASCM_RD_I8(0) == (ir & CSX_CORE_THUMB_ASCM_RD_I8_MASK))
					return(csx_core_thumb_ascm_rd_i(core, ir));
				break;
			case	0x4000:
				if(CSX_CORE_THUMB_DP_RMS_RDN == (ir & CSX_CORE_THUMB_DP_RMS_RDN_MASK))
					return(csx_core_thumb_dp_rms_rdn(core, ir));
				break;
			case	0x4400:
				if(CSX_CORE_THUMB_SDP_RMS_RDN(0) == (ir & CSX_CORE_THUMB_SDP_RMS_RDN_MASK))
					return(csx_core_thumb_sdp_rms_rdn(core, ir));
				break;
			case	0x4700:
				if(CSX_CORE_THUMB_BX == (ir & CSX_CORE_THUMB_BX_MASK))
					return(csx_core_thumb_bx(core, ir));
				break;
			case	0x5000:
				if(CSX_CORE_THUMB_LDST_RM_RN_RD == (ir & CSX_CORE_THUMB_LDST_RM_RN_RD_MASK))
					return(csx_core_thumb_ldst_rm_rn_rd(core, ir));
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
			case	0xb000:
				if(CSX_CORE_THUMB_ADD_SUB_SP_I7 == (ir & CSX_CORE_THUMB_ADD_SUB_SP_I7_MASK))
					return(csx_core_thumb_add_sub_sp_i7(core, ir));
				break;
			case	0xb400:
			case	0xbc00:
				if(CSX_CORE_THUMB_POP_PUSH(0) == (ir & CSX_CORE_THUMB_POP_PUSH_MASK))
					return(csx_core_thumb_pop_push(core, ir));
				break;
			case	0xc000:
				if(CSX_CORE_THUMB_LDSTM_RN_RXX(0) == (ir & CSX_CORE_THUMB_LDSTM_RN_RXX_MASK))
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
			default:
//				TRACE("ir = 0x%04x, opcode = 0x%04x, lsb = 0x%02x", ir, opcode, lsb);
				break;
		/* **** */
		}
	}//while(lsb-- > 8);

	TRACE("ir = 0x%04x, opcode = 0x%04x, lsb = 0x%02x", ir, opcode, lsb);

	csx_core_thumb_disasm(core, pc, ir);
	LOG_ACTION(exit(1));
}
