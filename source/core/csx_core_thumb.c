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
	CORE_T(const int cce = 1);

	const int bit_i = BEXT(opcode, 10);
	const uint8_t op2 = BEXT(opcode, 9);

	const csx_reg_t rm = _MLBFX(opcode, 8, 6);
	uint32_t rm_v = rm;
	if(!bit_i)
		rm_v = csx_reg_get(core, rm);
	
	const csx_reg_t rn = _MLBFX(opcode, 5, 3);
	const uint32_t rn_v = csx_reg_get(core, rn);
	const csx_reg_t rd = _MLBFX(opcode, 2, 0);
	
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

	if(op2)
		csx_core_flags_nzcv_sub(core, rd_v, rn_v, rm_v);
	else
		csx_core_flags_nzcv_add(core, rd_v, rn_v, rm_v);
}

static void csx_core_thumb_add_sub_sp_i7(csx_core_p core, uint16_t opcode)
{
	CORE_T(const int cce = 1);

	const int sub = BEXT(opcode, 7);
	const uint16_t imm7 = _MLBFMOV(opcode, 6, 0, 2);

	const uint32_t sp_v = csx_reg_get(core, rSP);
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

static void csx_core_thumb_add_rd_pcsp_i(csx_core_p core, uint16_t opcode)
{
	CORE_T(const int cce = 1);
	
	const int pcsp = BEXT(opcode, 11);
	const csx_reg_t rd = _MLBFX(opcode, 10, 8);
	const uint16_t imm8 = _MLBFMOV(opcode, 7, 0, 2);
	
	uint32_t rd_v;
	if(pcsp)
		rd_v = csx_reg_get(core, rSP);
	else
		rd_v = csx_reg_get(core, rPC) & ~3;
	
	uint32_t res = rd_v + imm8;

//	LOG("rPC:rSP");
	CORE_TRACE("add(%s, %s, 0x%03x); /* 0x%08x + 0x%03x = 0x%08x */",
				_arm_reg_name(rd), pcsp ? "rSP" : "rPC", imm8, rd_v, imm8, res);
	
	csx_reg_set(core, rd, res);
}


static void csx_core_thumb_ascm_rd_i(csx_core_p core, uint16_t opcode)
{
	CORE_T(const int cce = 1);
	int wb = 1;
	
	const uint8_t operation = _MLBFX(opcode, 12, 11);
	const csx_reg_t rd = _MLBFX(opcode, 10, 8);
	const uint32_t rd_v = csx_reg_get(core, rd);
	const uint8_t imm8 = _MLBFX(opcode, 7, 0);
	
	uint32_t res = rd_v;
	
	switch(operation)
	{
		case THUMB_ASCM_OP_ADD:
			res += imm8;
			CORE_TRACE("adds(%s, 0x%03x); /* 0x%08x + 0x%03x = 0x%08x */",
				_arm_reg_name(rd), imm8, rd_v, imm8, res);
			break;
		case THUMB_ASCM_OP_CMP:
			wb = 0;
			res -= imm8;
			CORE_TRACE("cmp(%s, 0x%03x); /* 0x%08x - 0x%03x = 0x%08x */",
				_arm_reg_name(rd), imm8, rd_v, imm8, res);
			break;
		case THUMB_ASCM_OP_MOV:
			res = imm8;
			CORE_TRACE("movs(%s, 0x%03x);", _arm_reg_name(rd), imm8);
			break;
		case THUMB_ASCM_OP_SUB:
			res -= imm8;
			CORE_TRACE("subs(%s, 0x%03x); /* 0x%08x - 0x%03x = 0x%08x */",
				_arm_reg_name(rd), imm8, rd_v, imm8, res);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			csx_core_thumb_disasm(core, csx_reg_get(core, rTEST(rPC)), opcode);
			LOG_ACTION(exit(1));
	}
	
	if(wb)
		csx_reg_set(core, rd, res);
	
	switch(operation)
	{
		case THUMB_ASCM_OP_ADD:
			csx_core_flags_nzcv_add(core, res, rd_v, imm8);
			break;
		case THUMB_ASCM_OP_CMP:
		case THUMB_ASCM_OP_SUB:
			csx_core_flags_nzcv_sub(core, res, rd_v, imm8);
			break;
		case THUMB_ASCM_OP_MOV:
			csx_core_flags_nz(core, res);
			break;
	}
}

static void csx_core_thumb_bxx(csx_core_p core, uint16_t opcode0)
{
	CORE_T(const int cce = 1);
	
	uint32_t pc = IP;
	uint32_t eao = 0;

	if(0x2 == _MLBFX(opcode0, 12, 11))
	{
		eao = _MLBFSEXT(opcode0, 10, 0) << 12;
	}	
	else
	{
		csx_core_thumb_disasm(core, pc, opcode0);
		UNPREDICTABLE;
	}
	
	const uint32_t lr = pc + eao;

	if(0) LOG("rLR == (0x%08x + 0x%08x) == 0x%08x", pc, eao, lr);

	pc += 2;
	uint16_t opcode1 = csx_mmu_read(core->csx->mmu, pc & ~1, sizeof(uint16_t));
	uint32_t opcode = (opcode0 << 16) | opcode1;

	if(0) LOG("PC2 = 0x%08x, opcode = 0x%04x:0x%04x", pc, opcode0, opcode1);

	if((0x7 == _MLBFX(opcode, 15, 13)) && BEXT(opcode, 11))
	{
		pc += 2;
		
		const int bit_blx = (0 == BEXT(opcode, 12));
		eao += _MLBFMOV(opcode, 10, 0, 1);

		const uint32_t new_lr = pc | 1;
		const uint32_t new_pc = pc + eao;

		if(0) LOG("NEW_PC = 0x%08x, NEW_LR = 0x%08x", new_pc, new_lr & ~1);

		CORE_TRACE("bl%s(0x%08x); /* 0x%08x + 0x%08x, LR = 0x%08x */",
			bit_blx ? "x" : "", new_pc & ~1, pc, eao, new_lr & ~1);

		if(bit_blx)
		{
			CORE_TRACE_BRANCH(new_pc & ~3);
			csx_reg_set(core, rTHUMB(rPC), new_pc & ~3);
		}
		else
		{
			CORE_TRACE_BRANCH(new_pc);
			csx_reg_set(core, rPC, new_pc);
		}

		CORE_TRACE_LINK(new_lr);
		csx_reg_set(core, rLR, new_lr);
	}
	else
	{
		csx_reg_set(core, rPC, pc);
		csx_reg_set(core, rLR, lr | 1);
		
		
		LOG("PC = 0x%08x, LR = 0x%08x", pc, lr);
		UNPREDICTABLE;
	}
}

static void csx_core_thumb_bx(csx_core_p core, uint16_t opcode)
{
	CORE_T(const int cce = 1);

	const int tsbz = _check_sbz(opcode, 2, 0, 0, 0);
	if(tsbz)
		LOG_ACTION(exit(1));

	const csx_reg_t rm = _MLBFX(opcode, 6, 3);
	const int link = BEXT(opcode, 7);
	
	const uint32_t new_pc = csx_reg_get(core, rm);
	const int thumb = new_pc & 1;

	CORE_TRACE("b%sx(%s); /* %c(0x%08x) */",
		link ? "l" : "", _arm_reg_name(rm),
		thumb ? 'T' : 'A', new_pc & ~1);

	if(link) {
		const uint32_t new_lr = csx_reg_get(core, rTEST(rPC)) | 1;
		CORE_TRACE_LINK(new_lr);
		csx_reg_set(core, rLR, new_lr);
	}
	
	CORE_TRACE_BRANCH(new_pc);
	csx_reg_set(core, rTHUMB(rPC), new_pc);
	if(0) LOG("PC(0x%08x)", csx_reg_get(core, rTEST(rPC)));
}

static void csx_core_thumb_bcc(csx_core_p core, uint16_t opcode)
{
	const uint8_t cond = _MLBFX(opcode, 11, 8);
	const uint8_t cce = csx_core_check_cc(core, opcode, cond);
	const int32_t imm8 = _MLBFSEXT(opcode, 7, 0) << 1;

	const uint32_t pc = csx_reg_get(core, rPC);
	const uint32_t new_pc = pc + imm8;

	CORE_TRACE("b(0x%08x); /* 0x%08x + 0x%03x cce = %u */", new_pc & ~1, pc, imm8, cce);

	CORE_TRACE_BRANCH_CC(new_pc);

	if(cce)
	{
		csx_reg_set(core, rPC, new_pc);
	}
}

static void csx_core_thumb_dp_rms_rdn(csx_core_p core, uint16_t opcode)
{
	CORE_T(const int cce = 1);
	
	const uint8_t operation = _MLBFX(opcode, 9, 6);

	const csx_reg_t rm = _MLBFX(opcode, 5, 3);
	const uint32_t rm_v = csx_reg_get(core, rm);
	
	const csx_reg_t rd = _MLBFX(opcode, 2, 0);
	const uint32_t rd_v = csx_reg_get(core, rd);
	
	uint32_t res = rd_v;
	
	switch(operation)
	{
		case THUMB_DP_OP_AND:
			res &= rm_v;
			CORE_TRACE("ands(%s, %s); /* 0x%08x & 0x%08x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), rd_v, rm_v, res);
			break;
		case THUMB_DP_OP_BIC:
			res &= ~rm_v;
			CORE_TRACE("bics(%s, %s); /* 0x%08x & ~0x%08x(0x%08x) = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), rd_v, rm_v, ~rm_v, res);
			break;
		case THUMB_DP_OP_MVN:
			res = ~rm_v;
			CORE_TRACE("mvns(%s, %s); /* ~0x%08x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), rm_v, res);
			break;
		case THUMB_DP_OP_ORR:
			res |= rm_v;
			CORE_TRACE("orrs(%s, %s); /* 0x%08x | 0x%08x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), rd_v, rm_v, res);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			csx_core_thumb_disasm(core, IP, opcode);
			LOG_ACTION(exit(1));
			break;
	}

	csx_reg_set(core, rd, res);
	csx_core_flags_nz(core, res);
}

static void csx_core_thumb_ldst_rd_i(csx_core_p core, uint16_t opcode)
{
	const csx_mmu_p mmu = core->csx->mmu;

//	core->ccs = "EA"; /* ??? */
	CORE_T(const int cce = 1);
	
	const uint16_t operation = _MLBFTST(opcode, 15, 12);
	const int bit_l = BEXT(opcode, 11);
	const csx_reg_t rd = _MLBFX(opcode, 10, 8);
	const uint16_t imm8 = _MLBFMOV(opcode, 7, 0, 2);

	uint8_t rn;
	uint32_t ea;
	switch(operation)
	{
		case	0x4000:
			rn = rPC;
			ea = csx_reg_get(core, rPC) & ~0x03;
			break;
		case	0x9000:
			rn = rSP;
			ea = csx_reg_get(core, rSP);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			csx_core_thumb_disasm(core, IP, opcode);
			LOG_ACTION(exit(1));
			break;
	}

	ea += imm8;

	uint32_t rd_v;
	
	if(bit_l)
		rd_v = csx_mmu_read(mmu, ea, sizeof(uint32_t));
	else
		rd_v = csx_reg_get(core, rd);

	CORE_TRACE("%s(%s, %s[0x%03x]); /* [0x%08x](0x%08x) */",
		bit_l ? "ldr" : "str", _arm_reg_name(rd), _arm_reg_name(rn), imm8, ea, rd_v);

	if(bit_l)
		csx_reg_set(core, rd, rd_v);
	else
		csx_mmu_write(mmu, ea, rd_v, sizeof(uint32_t));
}

static void csx_core_thumb_ldst_bwh_o_rn_rd(csx_core_p core, uint16_t opcode)
{
	CORE_T(const int cce = 1);
	
//	struct {
		const int bit_b = BEXT(opcode, 12);
		const int bit_l = BEXT(opcode, 11);
//	}bit;
	
	const uint8_t imm5 = _MLBFX(opcode, 10, 6);
	const csx_reg_t rn = _MLBFX(opcode, 5, 3);
	const uint32_t rn_v = csx_reg_get(core, rn);
	const csx_reg_t rd = _MLBFX(opcode, 2, 0);
	
	const char *ss = "";
	uint8_t size = 0;
	
	if(CSX_CORE_THUMB_LDST_BW_O_RN_RD == (opcode & CSX_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
	{
		if(bit_b)
		{
			ss = "b";
			size = sizeof(uint8_t);
		}
		else
		{
			size = sizeof(uint32_t);
		}
	}
	else
	{
		ss = "h";
		size = sizeof(uint16_t);
	}
	
	assert(size != 0);
	
	uint16_t offset = imm5 << (size >> 1);
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
	CORE_T(const int cce = 1);
	
//	struct {
		const int bit_l = BEXT(opcode, 11);
		const uint8_t bwh = _MLBFX(opcode, 10, 9);
//	}bit;
	
	const csx_reg_t rm = _MLBFX(opcode, 8, 6);
	const uint32_t rm_v = csx_reg_get(core, rm);
	
	const csx_reg_t rn = _MLBFX(opcode, 5, 3);
	const uint32_t rn_v = csx_reg_get(core, rn);
	
	const csx_reg_t rd = _MLBFX(opcode, 2, 0);
	
	const char *ss = "";
	uint8_t size = 0;
	
	switch(bwh)
	{
		case 0x00:
			size = sizeof(uint32_t);
		break;
		case 0x01:
			ss = "h";
			size = sizeof(uint16_t);
		break;
		case 0x02:
			ss = "b";
			size = sizeof(uint8_t);
		break;
		default:
			LOG("bwh = 0x%01x", bwh);
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
	const csx_p csx = core->csx;
	CORE_T(const int cce = 1);

//	struct {
		const int bit_l = BEXT(opcode, 11);
//	}bit;

	const csx_reg_t rn = _MLBFX(opcode, 10, 8);
	const uint32_t rn_v = csx_reg_get(core, rn);

	const uint8_t rlist = _MLBFX(opcode, 7, 0);
	
	const uint32_t start_address = rn_v;
	const uint32_t end_address = start_address + (__builtin_popcount(rlist) << 2) - 4;
	
	uint32_t ea = start_address;

	/* CP15_r1_Ubit == 0 */
	assert(0 == (ea & 3));

	char reglist[9];

	for(int i = 0; i <= 7; i++)
	{
		int rxx = BEXT(rlist, i);
		reglist[i] = rxx ? ('0' + i) : '.';

		if(rxx)
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
			ea += sizeof(uint32_t);
		}
	}
	
	assert(end_address == ea - 4);
	
	int wb = bit_l && (0 == BTST(rlist, rn));
	wb |= !bit_l && !(rlist & _BM(rn - 1));
	
	if(wb)
		csx_reg_set(core, rn, ea);

	reglist[8] = 0;

	CORE_TRACE("%smia(%s%s, r{%s}); /* 0x%08x */",
		bit_l ? "ld" : "st", _arm_reg_name(rn),
		wb ? "!" : "", reglist, rn_v);
}

static void csx_core_thumb_sbi_imm5_rm_rd(csx_core_p core, uint16_t opcode)
{
	CORE_T(const int cce = 1);
	
	const uint8_t operation = _MLBFX(opcode, 12, 11);
	const uint8_t imm5 = _MLBFX(opcode, 10, 6);

	const csx_reg_t rm = _MLBFX(opcode, 5, 3);
	const uint32_t rm_v = csx_reg_get(core, rm);

	const csx_reg_t rd = _MLBFX(opcode, 2, 0);
	
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
				rd_v = rm31_c ? ~0 : 0;
			}
			break;
		case THUMB_SBI_OP_LSL:
			ops = "lsl";
			if(shift)
			{
				BMAS(CPSR, CSX_PSR_BIT_C, BEXT(rm_v, (-shift & 31)));
				rd_v = rm_v << shift;
			}
			break;
		case THUMB_SBI_OP_LSR:
			ops = "lsr";
			if(shift)
				rd_v = rm_v >> shift;
			else
				shift = 32;
			BMAS(CPSR, CSX_PSR_BIT_C, BEXT(rm_v, (shift - 1)));
			break;
		default:
			LOG("operation = 0x%01x", operation);
			LOG_ACTION(exit(1));
	}
	
	csx_core_flags_nz(core, rd_v);
	
	if(0) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & CSX_PSR_N), !!(CPSR & CSX_PSR_Z),
		!!(CPSR & CSX_PSR_C), !!(CPSR & CSX_PSR_V));

	CORE_TRACE("%ss(%s, %s, 0x%02x); /* %s(0x%08x, 0x%02x) = 0x%08x */",
		ops, _arm_reg_name(rd), _arm_reg_name(rm), shift, ops, rm_v, shift, rd_v);
	
	csx_reg_set(core, rd, rd_v);
}

static void csx_core_thumb_pop_push(csx_core_p core, uint16_t opcode)
{
	CORE_T(const int cce = 1);
	
	const csx_p csx = core->csx;
	const csx_mmu_p mmu = csx->mmu;
	
//	struct {
		const int bit_l = BEXT(opcode, 11);
		const int bit_r = BEXT(opcode, 8);
//	}bit;
	
	const uint8_t rlist = _MLBFX(opcode, 7, 0);

	const uint32_t sp_v = csx_reg_get(core, rSP);
	
	const uint8_t rcount = (bit_r + __builtin_popcount(rlist)) << 2;

	uint32_t start_address = sp_v;
	uint32_t end_address = sp_v;
	
	if(bit_l)
	{ /* pop */
		end_address += rcount;
	}
	else
	{ /* push */
		start_address -= rcount;
		end_address -= 4;
	}
	
	/* CP15_reg1_Abit == 0 && CP15_reg1_Ubit == 0 */
	uint32_t ea = start_address & ~3;
	
	uint32_t rxx_v;
	char reglist[9];

	for(int i = 0; i <=7; i++)
	{
		int rxx = BEXT(rlist, i);
		reglist[i] = rxx ? ('0' + i) : '.';

		if(rxx)
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
			ea += sizeof(uint32_t);
		}
	}

	CORE_T(const char *pclrs = bit_r ? (bit_l ? ", PC" : ", LR") : "");
	reglist[8] = 0;
	CORE_TRACE("%s(rSP, r{%s%s});", bit_l ? "pop" : "push", reglist, pclrs);

	if(bit_r)
	{
		if(bit_l)
		{ /* pop */
			rxx_v = csx_mmu_read(mmu, ea, sizeof(uint32_t));
			csx_reg_set(core, rTHUMB(rPC), rxx_v);
		}
		else
		{ /* push */
			rxx_v = csx_reg_get(core, rLR);
			csx_mmu_write(mmu, ea, rxx_v, sizeof(uint32_t));
		}
		ea += sizeof(uint32_t);
	}
	
	if(0) LOG("SP = 0x%08x, PC = 0x%08x", sp_v, csx_reg_get(core, rTEST(rPC)));
	
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
	CORE_T(const int cce = 1);
	
	const uint8_t operation = _MLBFX(opcode, 9, 8);

	const csx_reg_t rm = _MLBFX(opcode, 6, 3);
	const uint32_t rm_v = csx_reg_get(core, rm);

	const csx_reg_t rd = _MLBFX(opcode, 2, 0) | BMOV(opcode, 7, 3);
	const uint32_t rd_v = csx_reg_get(core, rd);
	
	uint32_t res = rd_v;
	
	switch(operation)
	{
		case THUMB_SDP_OP_ADD:
			res += rm_v;
			CORE_TRACE("add(%s, %s); /* 0x%08x + 0x%08x = 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), rd_v, rm_v, res);
			break;
		case THUMB_SDP_OP_MOV:
			res = rm_v;
			CORE_TRACE("mov(%s, %s); /* 0x%08x */",
				_arm_reg_name(rd), _arm_reg_name(rm), res);
			break;
		default:
			LOG("operation = 0x%01x", operation);
			csx_core_thumb_disasm(core, IP, opcode);
			LOG_ACTION(exit(1));
			break;
	}

	csx_reg_set(core, rd, res);
}

/* **** */

void csx_core_thumb_step(csx_core_p core)
{
	CORE_T(core->ccs = "AL");

	uint32_t pc;
	const uint32_t ir = csx_reg_pc_fetch_step(core, &pc);

	uint8_t lsb;
	uint32_t opcode;
	
	for(lsb = 8; lsb <= 13; lsb++)
	{
		opcode = ir & _MLBF(15, lsb);

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
			case	0x4800:
				if(CSX_CORE_THUMB_LDST_PC_RD_I == (ir & CSX_CORE_THUMB_LDST_PC_RD_I_MASK))
					return(csx_core_thumb_ldst_rd_i(core, ir));
				break;
			case	0x5000:
				if(CSX_CORE_THUMB_LDST_RM_RN_RD == (ir & CSX_CORE_THUMB_LDST_RM_RN_RD_MASK))
					return(csx_core_thumb_ldst_rm_rn_rd(core, ir));
				break;
			case	0x5600:
			case	0x5e00:
				break;
			case	0x6000:
				if(CSX_CORE_THUMB_LDST_BW_O_RN_RD == (ir & CSX_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
					return(csx_core_thumb_ldst_bwh_o_rn_rd(core, ir));
				break;
			case	0x8000:
				if(CSX_CORE_THUMB_LDST_H_O_RN_RD == (ir & CSX_CORE_THUMB_LDST_H_O_RN_RD_MASK))
					return(csx_core_thumb_ldst_bwh_o_rn_rd(core, ir));
				break;
			case	0x9000:
				if(CSX_CORE_THUMB_LDST_SP_RD_I == (ir & CSX_CORE_THUMB_LDST_SP_RD_I_MASK))
					return(csx_core_thumb_ldst_rd_i(core, ir));
				break;
			case	0xa000:
				if(CSX_CORE_THUMB_ADD_RD_PCSP_I == (ir & CSX_CORE_THUMB_ADD_RD_PCSP_I_MASK))
					return(csx_core_thumb_add_rd_pcsp_i(core, ir));
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
				opcode = ir & _MLBF(15, 8);
				switch(opcode)
				{
					case	0xde00: /* undefined */
					case	0xdf00: /* swi */
//						TRACE("ir = 0x%04x, opcode = 0x%04x, lsb", ir, opcode);
						break;
					default:
						return(csx_core_thumb_bcc(core, ir));
						break;
				} break;
			case	0xe000:
			case	0xf000:
					return(csx_core_thumb_bxx(core, ir));
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
