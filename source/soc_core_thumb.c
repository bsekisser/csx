#include <assert.h>

#include "csx.h"
#include "soc_core.h"
#include "soc_core_disasm.h"
#include "soc_core_utility.h"

#include "soc_core_thumb_inst.h"

#include "soc_core_reg_trace.h"

static void soc_core_thumb_add_rd_pcsp_i(soc_core_p core)
{
	const int pcsp = BEXT(IR, 11);
	rR(N) = pcsp ? rSP : rPC;
	vR(N) = pcsp ? SP : PC_THUMB;

	const uint16_t imm8 = mlBFMOV(IR, 7, 0, 2);

	soc_core_decode_get(core, rRD, 10, 8, 0);

	if(!pcsp)
		vR(N) &= ~3;

	vR(D) = vR(N) + imm8;

//	LOG("rPC:rSP");
	CORE_TRACE("add(%s, %s, 0x%03x); /* 0x%08x + 0x%03x = 0x%08x */",
				_arm_reg_name(rR(D)), pcsp ? "rSP" : "rPC", imm8, vR(N), imm8, vR(D));

	soc_core_reg_set(core, rR(D), vR(D));
}

static void soc_core_thumb_add_sub_rn_rd(soc_core_p core)
{
	const int bit_i = BEXT(IR, 10);
	const uint8_t op2 = BEXT(IR, 9);

	soc_core_decode_get(core, rRM, 8, 6, !bit_i);
	if(bit_i)
		vR(M) = rR(M);

	soc_core_decode_get(core, rRN, 5, 3, 1);
	soc_core_decode_get(core, rRD, 2, 0, 0);

	vR(D) = vR(N);

	if(op2)
	{
		vR(D) -= vR(M);
		if(bit_i)
		{
			CORE_TRACE("subs(%s, %s, 0x%01x); /* 0x%08x - 0x%01x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(N)), vR(M), vR(N), vR(M), vR(D));
		}
		else
		{
			CORE_TRACE("subs(%s, %s, %s); /* 0x%08x - 0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(N)), _arm_reg_name(rR(M)), vR(N), vR(M), vR(D));
		}
	}
	else
	{
		vR(D) += vR(M);
		if(bit_i)
		{
			CORE_TRACE("adds(%s, %s, 0x%01x); /* 0x%08x + 0x%01x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(N)), vR(M), vR(N), vR(M), vR(D));
		}
		else
		{
			CORE_TRACE("adds(%s, %s, %s); /* 0x%08x + 0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(N)), _arm_reg_name(rR(M)), vR(N), vR(M), vR(D));
		}
	}

	soc_core_reg_set(core, rR(D), vR(D));

	if(op2)
		soc_core_flags_nzcv_sub(core, vR(D), vR(N), vR(M));
	else
		soc_core_flags_nzcv_add(core, vR(D), vR(N), vR(M));
}

static void soc_core_thumb_add_sub_sp_i7(soc_core_p core)
{
	const int sub = BEXT(IR, 7);
	const uint16_t imm7 = mlBFMOV(IR, 6, 0, 2);

	_setup_rR_vR(N, rSP, SP);
	vR(D) = vR(N);

	if(sub)
	{
		vR(D) -= imm7;
		CORE_TRACE("sub(rSP, 0x%04x); /* 0x%08x - 0x%04x = 0x%08x */",
			imm7, vR(N), imm7, vR(D));
	}
	else
	{
		vR(D) += imm7;
		CORE_TRACE("add(rSP, 0x%04x); /* 0x%08x + 0x%04x = 0x%08x */",
			imm7, vR(N), imm7, vR(D));
	}

	SP = vR(D);
}

static void soc_core_thumb_ascm_rd_i(soc_core_p core)
{
	int wb = 1;

	const uint8_t operation = mlBFEXT(IR, 12, 11);
	const uint8_t imm8 = mlBFEXT(IR, 7, 0);

	soc_core_decode_get(core, rRD, 10, 8, 1);

	uint32_t res = vR(D);

	switch(operation)
	{
		case THUMB_ASCM_OP_ADD:
			res += imm8;
			CORE_TRACE("adds(%s, 0x%03x); /* 0x%08x + 0x%03x = 0x%08x */",
				_arm_reg_name(rR(D)), imm8, vR(D), imm8, res);
			break;
		case THUMB_ASCM_OP_CMP:
			wb = 0;
			res -= imm8;
			CORE_TRACE("cmp(%s, 0x%03x); /* 0x%08x - 0x%03x = 0x%08x */",
				_arm_reg_name(rR(D)), imm8, vR(D), imm8, res);
			break;
		case THUMB_ASCM_OP_MOV:
			res = imm8;
			CORE_TRACE("movs(%s, 0x%03x);", _arm_reg_name(rR(D)), imm8);
			break;
		case THUMB_ASCM_OP_SUB:
			res -= imm8;
			CORE_TRACE("subs(%s, 0x%03x); /* 0x%08x - 0x%03x = 0x%08x */",
				_arm_reg_name(rR(D)), imm8, vR(D), imm8, res);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			soc_core_disasm_thumb(core, IP, IR);
			LOG_ACTION(exit(1));
	}

	if(wb)
		soc_core_reg_set(core, rR(D), res);

	switch(operation)
	{
		case THUMB_ASCM_OP_ADD:
			soc_core_flags_nzcv_add(core, res, vR(D), imm8);
			break;
		case THUMB_ASCM_OP_CMP:
		case THUMB_ASCM_OP_SUB:
			soc_core_flags_nzcv_sub(core, res, vR(D), imm8);
			break;
		case THUMB_ASCM_OP_MOV:
			soc_core_flags_nz(core, res);
			break;
	}
}

static void soc_core_thumb_bcc(soc_core_p core)
{
	const uint8_t cond = mlBFEXT(IR, 11, 8);
	const int32_t imm8 = mlBFEXTs(IR, 7, 0) << 1;

	CCx.e = soc_core_check_cc(core, cond);

	const uint32_t new_pc = PC_THUMB + imm8;

	CORE_TRACE("b(0x%08x); /* 0x%08x + 0x%03x cce = %u */", new_pc & ~1, PC_THUMB, imm8, CCx.e);

	CORE_TRACE_BRANCH_CC(new_pc);

	if(CCx.e)
	{
		PC = new_pc;
	}
}

static void soc_core_thumb_bx(soc_core_p core)
{
	const int tsbz = _check_sbz(IR, 2, 0, 0, 0);
	if(tsbz)
		LOG_ACTION(exit(1));

	soc_core_decode_get(core, rRM, 6, 3, 1);

	const int link = BEXT(IR, 7);

	const uint32_t new_pc = vR(M);
	const int thumb = new_pc & 1;

	CORE_TRACE("b%sx(%s); /* %c(0x%08x) */",
		link ? "l" : "", _arm_reg_name(rR(M)),
		thumb ? 'T' : 'A', new_pc & ~1);

	if(link) {
		const uint32_t new_lr = PC | 1;
		CORE_TRACE_LINK(new_lr);
		LR = new_lr;
	}

	CORE_TRACE_BRANCH(new_pc);
	soc_core_reg_set_pcx(core, new_pc);
	if(0) LOG("PC(0x%08x)", PC);
}

static void soc_core_thumb_bxx_b(soc_core_p core, int32_t eao)
{
	uint32_t new_pc = PC + eao;

	CORE_TRACE("b(0x%08x); /* 0x%08x + 0x%03x*/", new_pc & ~1, PC, eao);

	PC = new_pc;
}

static void soc_core_thumb_bxx_blx(
	soc_core_p core,
	int32_t eao)
{
	uint32_t new_pc = (LR + eao);

	if(1) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);

	LR = PC | 1;

	int blx = (0 == BEXT(IR, 12));

	if(blx)
		new_pc &= ~3;

	CORE_TRACE("bl%s(0x%08x); /* 0x%08x + 0x%08x, LR = 0x%08x */",
		blx ? "x" : "", new_pc & ~1, PC, eao, LR & ~1);

	if(blx)
		soc_core_reg_set_pcx(core, new_pc);
	else
		PC = new_pc & ~1;

	if(1) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);
}

static void soc_core_thumb_bxx(soc_core_p core)
{
	for(int i = 0; i < 2; i++) {
		int32_t eao = mlBFEXTs(IR, 10, 0);
		uint8_t h = mlBFEXT(IR, 12, 11);

		if(0) CORE_TRACE("H = 0x%02x, LR = 0x%08x, PC = 0x%08x, EAO = 0x%08x",
			h, LR, PC, eao);

		switch(h) {
			case 0x00:
				/* branch offset is from PC + 4, ie.. lr */
				return(soc_core_thumb_bxx_b(core, eao << 1));
			case 0x01:
			case 0x03:
				eao = mlBFMOV(IR, 10, 0, 1);
				return(soc_core_thumb_bxx_blx(core, eao));
			case 0x02:
				eao <<= 12;
				LR = 2 + PC + eao;

				IR <<= 16;
				IR += soc_core_read(core, PC & ~1, sizeof(uint16_t));

				if((0x7 != mlBFEXT(IR, 15, 13)) && !BEXT(IR, 11)) {
					CORE_TRACE("/* xxx -- LR = 0x%08x + 0x%03x = 0x%08x */", PC, eao, LR);
					return;
				}

				PC += 2;

				break;
		}
	}
}

static void soc_core_thumb_dp_rms_rdn(soc_core_p core)
{
	const uint8_t operation = mlBFEXT(IR, 9, 6);

	soc_core_decode_get(core, rRM, 5, 3, 1);
	soc_core_decode_get(core, rRD, 2, 0, 1);

	uint32_t res = vR(D);
	int wb = 1;

	switch(operation)
	{
		case THUMB_DP_OP_AND:
			res &= vR(M);
			CORE_TRACE("ands(%s, %s); /* 0x%08x & 0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), vR(D), vR(M), res);
			break;
		case THUMB_DP_OP_BIC:
			res &= ~vR(M);
			CORE_TRACE("bics(%s, %s); /* 0x%08x & ~0x%08x(0x%08x) = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), vR(D), vR(M), ~vR(M), res);
			break;
		case THUMB_DP_OP_CMP:
			wb = 0;
			res -= vR(M);
			CORE_TRACE("cmps(%s, %s); /* 0x%08x - 0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), vR(D), vR(M), res);
			break;
		case THUMB_DP_OP_LSL:
			res <<= vR(M) & 0xff;
			CORE_TRACE("muls(%s, %s); /* 0x%08x - 0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), vR(D), vR(M), res);
			break;
		case THUMB_DP_OP_MUL:
			if(res !=0)
				res *= vR(M);
			CORE_TRACE("muls(%s, %s); /* 0x%08x * 0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), vR(D), vR(M), res);
			break;
		case THUMB_DP_OP_MVN:
			res = ~vR(M);
			CORE_TRACE("mvns(%s, %s); /* ~0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), vR(M), res);
			break;
		case THUMB_DP_OP_ORR:
			res |= vR(M);
			CORE_TRACE("orrs(%s, %s); /* 0x%08x | 0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), vR(D), vR(M), res);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			soc_core_disasm_thumb(core, IP, IR);
			LOG_ACTION(exit(1));
			break;
	}

	if(wb)
		soc_core_reg_set(core, rR(D), res);

	switch(operation) {
		case THUMB_DP_OP_CMP:
			soc_core_flags_nzcv_sub(core, res, rR(D), rR(M));
			break;
		case THUMB_DP_OP_LSL:
			CPSR &= ~CSX_PSR_NZC;

			CPSR |= BMOV(res, 31, CSX_PSR_BIT_N);
			CPSR |= ((res == 0) ? CSX_PSR_Z : 0);

			if(vR(M) < 32)
				CPSR |= BMOV(vR(D), vR(M), CSX_PSR_BIT_C);
			else
				CPSR |= BMOV(vR(D), 0, CSX_PSR_BIT_C);
			break;
		default:
			soc_core_flags_nz(core, res);
			break;
	}
}

static void soc_core_thumb_ldst_bwh_o_rn_rd(soc_core_p core)
{
//	struct {
		const int bit_b = BEXT(IR, 12);
		const int bit_l = BEXT(IR, 11);
//	}bit;

	const uint8_t imm5 = mlBFEXT(IR, 10, 6);

	soc_core_decode_get(core, rRN, 5, 3, 1);
	soc_core_decode_get(core, rRD, 2, 0, 0);

	const char *ss = "";
	uint8_t size = 0;

	if(CSX_CORE_THUMB_LDST_BW_O_RN_RD == (IR & CSX_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
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
	uint32_t ea = vR(N) + offset;

	if(bit_l)
		vR(D) = soc_core_read(core, ea, size);
	else
		vR(D) = soc_core_reg_get(core, rR(D));

	CORE_TRACE("%sr%s(%s, %s[0x%03x]); /* [(0x%08x + 0x%03x) = 0x%08x](0x%08x) */",
		bit_l ? "ld" : "st", ss, _arm_reg_name(rR(D)), _arm_reg_name(rR(N)), offset, vR(N), offset, ea, vR(D));

	if(bit_l)
		soc_core_reg_set(core, rR(D), vR(D));
	else
		soc_core_write(core, ea, vR(D), size);
}

static void soc_core_thumb_ldst_rd_i(soc_core_p core)
{
	const uint16_t operation = mlBFTST(IR, 15, 12);
	const int bit_l = BEXT(IR, 11);
	const uint16_t imm8 = mlBFMOV(IR, 7, 0, 2);

	soc_core_decode_get(core, rRD, 10, 8, 0);

	switch(operation)
	{
		case	0x4000:
			_setup_rR_vR(N, rPC, PC_THUMB & ~0x03);
			break;
		case	0x9000:
			_setup_rR_vR(N, rSP, SP);
			break;
		default:
			LOG("operation = 0x%03x", operation);
			soc_core_disasm_thumb(core, IP, IR);
			LOG_ACTION(exit(1));
			break;
	}

	vR(N) += imm8;

	if(bit_l)
		vR(D) = soc_core_read(core, vR(N), sizeof(uint32_t));
	else
		vR(D) = soc_core_reg_get(core, rR(D));

	CORE_TRACE("%s(%s, %s[0x%03x]); /* [0x%08x](0x%08x) */",
		bit_l ? "ldr" : "str", _arm_reg_name(rR(D)), _arm_reg_name(rR(N)), imm8, vR(N), vR(D));

	if(bit_l)
		soc_core_reg_set(core, rR(D), vR(D));
	else
		soc_core_write(core, vR(N), vR(D), sizeof(uint32_t));
}

static void soc_core_thumb_ldst_rm_rn_rd(soc_core_p core)
{
//	struct {
		const int bit_l = BEXT(IR, 11);
		const uint8_t bwh = mlBFEXT(IR, 10, 9);
//	}bit;

	soc_core_decode_get(core, rRM, 8, 6, 1);
	soc_core_decode_get(core, rRN, 5, 3, 1);
	soc_core_decode_get(core, rRD, 2, 0, 0);

	const char *ss = "";
	uint8_t size = 0;

	switch(bwh)
	{
		case 0x00:
			size = sizeof(uint32_t);
		break;
		case 0x01:
		case 0x07:
			ss = "h";
			size = sizeof(uint16_t);
		break;
		case 0x02:
		case 0x03:
			ss = "b";
			size = sizeof(uint8_t);
		break;
		default:
			LOG("bwh = 0x%01x", bwh);
			soc_core_disasm_thumb(core, IP, IR);
			LOG_ACTION(exit(1));
			break;
	}

	uint32_t ea = vR(N) + vR(M);

	if(bit_l)
		vR(D) = soc_core_read(core, ea, size);
	else
		vR(D) = soc_core_reg_get(core, rR(D));

	if(bit_l) {
		switch(bwh) {
			case 0x03:
				vR(D) = (int8_t)vR(D);
				break;
			case 0x07:
				vR(D) = (int16_t)vR(D);
				break;
		}
	}

	CORE_TRACE("%sr%s(%s, %s, %s); /* 0x%08x[0x%08x](0x%08x) = 0x%08x */",
		bit_l ? "ld" : "st", ss, _arm_reg_name(rR(D)), _arm_reg_name(rR(N)), _arm_reg_name(rR(M)), vR(N), vR(M), ea, vR(D));

	if(bit_l)
		soc_core_reg_set(core, rR(D), vR(D));
	else
		soc_core_write(core, ea, vR(D), size);
}

static void soc_core_thumb_ldstm_rn_rxx(soc_core_p core)
{
//	struct {
		const int bit_l = BEXT(IR, 11);
//	}bit;

	soc_core_decode_get(core, rRN, 10, 8, 1);

	const uint8_t rlist = mlBFEXT(IR, 7, 0);

	const uint32_t start_address = vR(N);
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
			CYCLE++;

			if(bit_l)
			{
				rxx_v = soc_core_read(core, ea, sizeof(uint32_t));
				soc_core_reg_set(core, i, rxx_v);
			}
			else
			{
				rxx_v = soc_core_reg_get(core, i);
				soc_core_write(core, ea, rxx_v, sizeof(uint32_t));
			}
			ea += sizeof(uint32_t);
		}
	}

	assert(end_address == ea - 4);

	const int wb_l = bit_l && (0 == BTST(rlist, rR(N)));
	const int wb = !bit_l || wb_l;

	if(wb)
		soc_core_reg_set(core, rR(N), ea);

	reglist[8] = 0;

	CORE_TRACE("%smia(%s%s, r{%s}); /* 0x%08x */",
		bit_l ? "ld" : "st", _arm_reg_name(rR(N)),
		wb ? "!" : "", reglist, vR(N));
}

static void soc_core_thumb_pop_push(soc_core_p core)
{
//	struct {
		const int bit_l = BEXT(IR, 11);
		const int bit_r = BEXT(IR, 8);
//	}bit;

	const uint8_t rlist = mlBFEXT(IR, 7, 0);

	const uint32_t sp_v = SP;

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
			CYCLE++;
			if(bit_l)
			{ /* pop */
				rxx_v = soc_core_read(core, ea, sizeof(uint32_t));
				if(0) LOG("ea = 0x%08x, r(%u) = 0x%08x", ea, i, rxx_v);
				soc_core_reg_set(core, i, rxx_v);
			}
			else
			{ /* push */
				rxx_v = soc_core_reg_get(core, i);
				if(0) LOG("ea = 0x%08x, r(%u) = 0x%08x", ea, i, rxx_v);
				soc_core_write(core, ea, rxx_v, sizeof(uint32_t));
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
			rxx_v = soc_core_read(core, ea, sizeof(uint32_t));
			if(1/*(_arm_version >= ARMv5)*/)
				soc_core_reg_set_pcx(core, rxx_v);
			else
				soc_core_reg_set(core, rPC, rxx_v);
		}
		else
		{ /* push */
			rxx_v = LR;
			soc_core_write(core, ea, rxx_v, sizeof(uint32_t));
		}
		ea += sizeof(uint32_t);
	}

	if(0) LOG("SP = 0x%08x, PC = 0x%08x", sp_v, PC);

	if(bit_l)
	{ /* pop */
		assert(end_address == ea);
		SP = end_address;
	}
	else
	{ /* push */
		assert(end_address == (ea - 4));
		SP = start_address;
	}
}

static void soc_core_thumb_sbi_imm5_rm_rd(soc_core_p core)
{
	const uint8_t operation = mlBFEXT(IR, 12, 11);
	const uint8_t imm5 = mlBFEXT(IR, 10, 6);

	soc_core_decode_get(core, rRM, 5, 3, 1);
	soc_core_decode_get(core, rRD, 2, 0, 0);

	uint8_t shift = imm5;
	const char *ops = "";

	switch(operation)
	{
		case THUMB_SBI_OP_ASR:
			ops = "asr";
			if(shift)
			{
				BMAS(CPSR, CSX_PSR_BIT_C, BEXT(vR(M), (shift - 1)));
				vR(D) = (((signed)vR(M)) >> shift);
			}
			else
			{
				int rm31_c = BEXT(vR(M), 31);
				BMAS(CPSR, CSX_PSR_BIT_C, rm31_c);
				vR(D) = rm31_c ? ~0 : 0;
			}
			break;
		case THUMB_SBI_OP_LSL:
			ops = "lsl";
			if(shift)
			{
				BMAS(CPSR, CSX_PSR_BIT_C, BEXT(vR(M), (-shift & 31)));
				vR(D) = vR(M) << shift;
			}
			break;
		case THUMB_SBI_OP_LSR:
			ops = "lsr";
			if(shift)
				vR(D) = vR(M) >> shift;
			else
				shift = 32;
			BMAS(CPSR, CSX_PSR_BIT_C, BEXT(vR(M), (shift - 1)));
			break;
		default:
			LOG("operation = 0x%01x", operation);
			LOG_ACTION(exit(1));
	}

	soc_core_flags_nz(core, vR(D));

	if(0) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & CSX_PSR_N), !!(CPSR & CSX_PSR_Z),
		!!(CPSR & CSX_PSR_C), !!(CPSR & CSX_PSR_V));

	CORE_TRACE("%ss(%s, %s, 0x%02x); /* %s(0x%08x, 0x%02x) = 0x%08x */",
		ops, _arm_reg_name(rR(D)), _arm_reg_name(rR(M)), shift, ops, vR(M), shift, vR(D));

	soc_core_reg_set(core, rR(D), vR(D));
}

static void soc_core_thumb_sdp_rms_rdn(soc_core_p core)
{
	const uint8_t operation = mlBFEXT(IR, 9, 8);

	soc_core_decode_get(core, rRM, 6, 3, 1);

	_setup_rR_vR(D,
		mlBFEXT(IR, 2, 0) | BMOV(IR, 7, 3),
		soc_core_reg_get(core, rR(D)));

	uint32_t res = vR(D);

	switch(operation)
	{
		case THUMB_SDP_OP_ADD:
			res += vR(M);
			CORE_TRACE("add(%s, %s); /* 0x%08x + 0x%08x = 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), vR(D), vR(M), res);
			break;
		case THUMB_SDP_OP_MOV:
			res = vR(M);
			CORE_TRACE("mov(%s, %s); /* 0x%08x */",
				_arm_reg_name(rR(D)), _arm_reg_name(rR(M)), res);
			break;
		default:
			LOG("operation = 0x%01x", operation);
			soc_core_disasm_thumb(core, IP, IR);
			LOG_ACTION(exit(1));
			break;
	}

	soc_core_reg_set(core, rR(D), res);
}

/* **** */

void soc_core_thumb_step(soc_core_p core)
{
	CCx.e = 1;
	CORE_T(CCx.s = "AL");

	IR = soc_core_reg_pc_fetch_step_thumb(core);

	uint8_t lsb;
	uint32_t opcode;

	for(lsb = 8; lsb <= 13; lsb++)
	{
		opcode = IR & mlBF(15, lsb);

		switch(opcode)
		{
		/* **** */
			case	0x0000:
				if(CSX_CORE_THUMB_SBI_IMM5_RM_RD == (IR & CSX_CORE_THUMB_SBI_IMM5_RM_RD_MASK))
					return(soc_core_thumb_sbi_imm5_rm_rd(core));
				break;
			case	0x1800:
				if(CSX_CORE_THUMB_ADD_SUB_RN_RD == (IR & CSX_CORE_THUMB_ADD_SUB_RN_RD_MASK))
					return(soc_core_thumb_add_sub_rn_rd(core));
				break;
			case	0x2000:
				if(CSX_CORE_THUMB_ASCM_RD_I8(0) == (IR & CSX_CORE_THUMB_ASCM_RD_I8_MASK))
					return(soc_core_thumb_ascm_rd_i(core));
				break;
			case	0x4000:
				if(CSX_CORE_THUMB_DP_RMS_RDN == (IR & CSX_CORE_THUMB_DP_RMS_RDN_MASK))
					return(soc_core_thumb_dp_rms_rdn(core));
				break;
			case	0x4400:
				if(CSX_CORE_THUMB_SDP_RMS_RDN(0) == (IR & CSX_CORE_THUMB_SDP_RMS_RDN_MASK))
					return(soc_core_thumb_sdp_rms_rdn(core));
				break;
			case	0x4700:
				if(CSX_CORE_THUMB_BX == (IR & CSX_CORE_THUMB_BX_MASK))
					return(soc_core_thumb_bx(core));
				break;
			case	0x4800:
				if(CSX_CORE_THUMB_LDST_PC_RD_I == (IR & CSX_CORE_THUMB_LDST_PC_RD_I_MASK))
					return(soc_core_thumb_ldst_rd_i(core));
				break;
			case	0x5000:
				if(CSX_CORE_THUMB_LDST_RM_RN_RD == (IR & CSX_CORE_THUMB_LDST_RM_RN_RD_MASK))
					return(soc_core_thumb_ldst_rm_rn_rd(core));
				break;
			case	0x5600:
			case	0x5e00:
				break;
			case	0x6000:
				if(CSX_CORE_THUMB_LDST_BW_O_RN_RD == (IR & CSX_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
					return(soc_core_thumb_ldst_bwh_o_rn_rd(core));
				break;
			case	0x8000:
				if(CSX_CORE_THUMB_LDST_H_O_RN_RD == (IR & CSX_CORE_THUMB_LDST_H_O_RN_RD_MASK))
					return(soc_core_thumb_ldst_bwh_o_rn_rd(core));
				break;
			case	0x9000:
				if(CSX_CORE_THUMB_LDST_SP_RD_I == (IR & CSX_CORE_THUMB_LDST_SP_RD_I_MASK))
					return(soc_core_thumb_ldst_rd_i(core));
				break;
			case	0xa000:
				if(CSX_CORE_THUMB_ADD_RD_PCSP_I == (IR & CSX_CORE_THUMB_ADD_RD_PCSP_I_MASK))
					return(soc_core_thumb_add_rd_pcsp_i(core));
				break;
			case	0xb000:
				if(CSX_CORE_THUMB_ADD_SUB_SP_I7 == (IR & CSX_CORE_THUMB_ADD_SUB_SP_I7_MASK))
					return(soc_core_thumb_add_sub_sp_i7(core));
				break;
			case	0xb400:
			case	0xbc00:
				if(CSX_CORE_THUMB_POP_PUSH(0) == (IR & CSX_CORE_THUMB_POP_PUSH_MASK))
					return(soc_core_thumb_pop_push(core));
				break;
			case	0xc000:
				if(CSX_CORE_THUMB_LDSTM_RN_RXX(0) == (IR & CSX_CORE_THUMB_LDSTM_RN_RXX_MASK))
					return(soc_core_thumb_ldstm_rn_rxx(core));
				break;
			case	0xd000:
				opcode = IR & mlBF(15, 8);
				switch(opcode)
				{
					case	0xde00: /* undefined */
					case	0xdf00: /* swi */
//						TRACE("ir = 0x%04x, opcode = 0x%04x, lsb", IP, opcode);
						break;
					default:
						return(soc_core_thumb_bcc(core));
						break;
				} break;
			case	0xe000:
			case	0xf000:
					return(soc_core_thumb_bxx(core));
				break;
			default:
//				TRACE("ir = 0x%04x, opcode = 0x%04x, lsb = 0x%02x", IR, opcode, lsb);
				break;
		/* **** */
		}
	}//while(lsb-- > 8);

	TRACE("ir = 0x%04x, opcode = 0x%04x, lsb = 0x%02x", IR, opcode, lsb);

	soc_core_disasm_thumb(core, IP, IR);
	LOG_ACTION(exit(1));
}
