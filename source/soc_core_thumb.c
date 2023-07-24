#define THUMB_IP_NEXT ((IP + 2) & ~1U)
#define THUMB_PC ((IP + 4) & ~1U)

#define rRvRvPC THUMB_PC

#include "soc_core_thumb.h"
#include "soc_core_thumb_inst.h"

#include "soc_core_disasm.h"
#include "soc_core_decode.h"
#include "soc_core_psr.h"
#include "soc_core_strings.h"
#include "soc_core_trace.h"
#include "soc_core_utility.h"

/* **** */

#include "csx_cp15_reg1.h"
#include "csx_soc_exception.h"

/* **** */

#include "bitfield.h"
#include "log.h"
#include "shift_roll.h"

/* **** */

#include "alubox_arm_shift.h"
#include "alubox_thumb.h"

/* **** */

static void soc_core_thumb_add_rd_pcsp_i(soc_core_p core)
{
	const int pcsp = BEXT(IR, 11);

	if(pcsp)
		_setup_rR_vR(N, rSP, SP);
	else
		_setup_rR_vR(N, rPC, THUMB_PC & ~3);

	const uint16_t imm8 = mlBFMOV(IR, 7, 0, 2);

	_setup_rR_dst_rR_src(core, rRD, mlBFEXT(IR, 10, 8), rRN);

	vR(D) += imm8;

	CORE_TRACE("add(%s, %s, 0x%03x); /* 0x%08x + 0x%03x = 0x%08x */",
				rR_NAME(D), rR_NAME(N), imm8, vR(N), imm8, vR(D));

	soc_core_reg_set(core, rR(D), vR(D));
}

static void soc_core_thumb_add_sub_rn_rd__rm(soc_core_p core, int bit_i)
{
	const uint8_t op2 = BEXT(IR, 9);

	soc_core_decode_dst(core, rRN, 5, 3);
	soc_core_decode_dst(core, rRD, 2, 0);

	const alubox_fn _alubox_fn[2] = { _alubox_thumb_adds, _alubox_thumb_subs };

	_alubox_fn[op2](core, &GPR(rR(D)));

	const char* ops[2] = { "adds", "subs" };
	const char opc[2] = { '+', '-' };

	if(bit_i)
	{
		if(op2 || vR(M)) {
			CORE_TRACE("%s(%s, %s, %01u); /* 0x%08x %c %01u = 0x%08x */",
				ops[op2], rR_NAME(D), rR_NAME(N), vR(M),
					vR(N), opc[op2], vR(M), vR(D));
		}
		else // pseudo op mov is encoded as adds rd, rn, 0
		{
			CORE_TRACE("mov(%s, %s); /* 0x%08x */",
				rR_NAME(D), rR_NAME(N), vR(D));
		}
	}
	else
	{
		CORE_TRACE("%s(%s, %s, %s); /* 0x%08x %c 0x%08x = 0x%08x */",
			ops[op2], rR_NAME(D), rR_NAME(N), rR_NAME(M),
			vR(N), opc[op2], vR(M), vR(D));
	}
}

static void soc_core_thumb_add_sub_rn_rd_imm3(soc_core_p core)
{
	_setup_rR_vR(M, ~0, mlBFEXT(IR, 8, 6));

	return(soc_core_thumb_add_sub_rn_rd__rm(core, 1));
}

static void soc_core_thumb_add_sub_rn_rd_rm(soc_core_p core)
{
	soc_core_decode_src(core, rRM, 8, 6);

	return(soc_core_thumb_add_sub_rn_rd__rm(core, 0));
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
	const uint8_t operation = mlBFEXT(IR, 12, 11);

	_setup_rR_vR(M, ~0, mlBFEXT(IR, 7, 0));
	soc_core_decode_dst(core, rRD, 10, 8);
	_setup_rR_dst(core, rRN, rR(D));

	const alubox_fn _alubox_fn[4] = {
		_alubox_thumb_movs, _alubox_thumb_cmps,
			_alubox_thumb_adds, _alubox_thumb_subs };

	_alubox_fn[operation](core, &GPR(rR(D)));

	const char* ops[4] = { "movs", "cmps", "adds", "subs" };
	const char opc[4] = { '=', '-', '+', '-' };

	switch(operation)
	{
		default:
			CORE_TRACE("%s(%s, 0x%03x); /* 0x%08x %c 0x%03x = 0x%08x */",
				ops[operation], rR_NAME(D),	vR(M),
					vR(N), opc[operation], vR(M), vR(D));
			break;
		case THUMB_ASCM_OP_MOV:
			CORE_TRACE("movs(%s, 0x%03x);", rR_NAME(D), vR(M));
			break;
	}
}

static void soc_core_thumb_bcc(soc_core_p core)
{
	const uint8_t cond = mlBFEXT(IR, 11, 8);
	const int32_t imm8 = mlBFMOVs(IR, 7, 0, 1);

	CCx.e = soc_core_check_cc(core, cond);

	const uint32_t new_pc = THUMB_PC + imm8;

	CORE_TRACE("b(0x%08x); /* 0x%08x + 0x%03x cce = 0x%08x */", new_pc & ~1, THUMB_PC, imm8, CCx.e);

	CORE_TRACE_BRANCH_CC(new_pc);

	if(CCx.e)
	{
		PC = new_pc & ~1U;
	}
}

static void soc_core_thumb_bx(soc_core_p core)
{
	const int tsbz = _check_sbz(IR, 2, 0, 0, 0);
	if(tsbz)
		LOG_ACTION(exit(1));

	soc_core_decode_src(core, rRM, 6, 3);

	const int link = BEXT(IR, 7);

	const uint32_t new_pc = vR(M);
	const int thumb = new_pc & 1;

	CORE_TRACE("b%sx(%s); /* %c(0x%08x) */",
		link ? "l" : "", rR_NAME(M),
		thumb ? 'T' : 'A', new_pc & ~1);

	if(link) {
		const uint32_t new_lr = THUMB_IP_NEXT | 1;
		CORE_TRACE_LINK(new_lr);
		LR = new_lr;
	}

	CORE_TRACE_BRANCH(new_pc);
	soc_core_reg_set_pcx(core, new_pc);
	if(0) LOG("PC(0x%08x)", PC);
}

static void soc_core_thumb_bxx_b(soc_core_p core)
{
	const int16_t eao = mlBFMOVs(IR, 10, 0, 1);
	const uint32_t new_pc = THUMB_PC + eao;

	int splat = _trace_bx_0 && (new_pc == THUMB_IP_NEXT);
	CORE_TRACE("b(0x%08x); /* 0x%08x + %s0x%03x*/",
		new_pc & ~1, PC, splat ? "x" : "", eao);

	PC = new_pc & ~1U;
}

static void soc_core_thumb_bxx__bl_blx(soc_core_p core, uint32_t eao, unsigned blx)
{
	const uint32_t new_pc = LR + eao;

	if(0) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);

	LR = PC | 1;

	int splat = _trace_bx_0 && (new_pc == THUMB_PC);
	CORE_TRACE("bl%s(0x%08x); /* 0x%08x + %s0x%08x, LR = 0x%08x */",
		blx ? "x" : "", new_pc & ~1, PC, splat ? "x" : "", eao, LR & ~1);

	PC = new_pc;
	soc_core_reg_set_thumb(core, 1 >> blx);

	if(0) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);
}

static void soc_core_thumb_bxx_bl(soc_core_p core)
{
	const uint32_t eao = mlBFMOV(IR, 10, 0, 1);

	return(soc_core_thumb_bxx__bl_blx(core, eao, 0));
}

static void soc_core_thumb_bxx_blx(soc_core_p core)
{
	const uint32_t eao = mlBFMOV(IR, 10, 0, 1);

	return(soc_core_thumb_bxx__bl_blx(core, eao, 1));
}

static void soc_core_thumb_bxx_prefix(soc_core_p core)
{
	const int32_t eao_prefix = mlBFMOVs(IR, 10, 0, 12);
	const uint8_t h_prefix = mlBFEXT(IR, 12, 11);

	if(2 == h_prefix) {
		LR = 2 + PC + eao_prefix;
	} else {
		DECODE_FAULT;
	}

	const uint32_t ir_suffix = soc_core_ifetch(core, PC & ~1, sizeof(uint16_t));

	if(0xe800 == (ir_suffix & 0xe800)) {
		const int blx = 1 ^ BEXT(ir_suffix, 12);

		if(blx && (ir_suffix & 1))
			goto not_prefix_suffix; /* undefined instruction */
		
		IR = (IR << 16) | ir_suffix;
		PC += 2;

		const uint32_t eao_suffix = mlBFMOV(IR, 10, 0, 1);

		return(soc_core_thumb_bxx__bl_blx(core, eao_suffix, blx));
	}
		
not_prefix_suffix:
	CORE_TRACE("BL/BLX(0x%08x)  /* LR = 0x%08x */", eao_prefix, LR);
}

static void soc_core_thumb_dp_rms_rdn(soc_core_p core)
{
	const uint8_t operation = mlBFEXT(IR, 9, 6);

	const alubox_fn _alubox_fn[16] = {
		_alubox_thumb_ands,	_alubox_thumb_eors,	_alubox_thumb_lsls,	_alubox_thumb_lsrs,
		_alubox_thumb_asrs,	_alubox_thumb_adcs,	_alubox_thumb_sbcs,	_alubox_thumb_rors,
		_alubox_thumb_tsts,	_alubox_thumb_negs,	_alubox_thumb_cmps,	_alubox_thumb_cmns,
		_alubox_thumb_orrs,	_alubox_thumb_muls,	_alubox_thumb_bics,	_alubox_thumb_mvns,
		};

	const char* _dpr_ops[2][16] = {{
		"ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
		"tsts", "negs", "cmps", "cmns", "orrs", "muls", "bics", "mvns",
		} , {
		"& ",	"^ ",	"<< ",	">> ",	"<<< ",	"+",	"-",	">><<",
		"& ",	"- ",	"- ",	"+ ",	"| ",	"* ",	"& ~",	"-",
		}};

	soc_core_decode_src(core, rRM, 5, 3);
	soc_core_decode_dst(core, rRD, 2, 0);
	_setup_rR_dst(core, rRN, rR(D));

	_alubox_fn[operation](core, &GPR(rR(D)));

	switch(operation)
	{
		default:
			CORE_TRACE("%s(%s, %s); /* 0x%08x %s0x%08x = 0x%08x */",
				_dpr_ops[0][operation], rR_NAME(D), rR_NAME(M),
				vR(N), _dpr_ops[1][operation], vR(M), vR(D));
			break;
		case THUMB_DP_OP_MVN:
			CORE_TRACE("mvns(%s, %s); /* ~0x%08x = 0x%08x */",
				rR_NAME(D), rR_NAME(M), vR(M), vR(D));
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

	soc_core_decode_src(core, rRN, 5, 3);
	soc_core_decode_dst(core, rRD, 2, 0);

	const char *ss = "";
	size_t size = 0;

	if(SOC_CORE_THUMB_LDST_BW_O_RN_RD == (IR & SOC_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
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

	const uint16_t offset = imm5 << (size >> 1);
	const uint32_t ea = vR(N) + offset;

	if(bit_l)
		vR(D) = soc_core_read(core, ea, size);
	else
		vR(D) = soc_core_reg_get(core, rR(D));

	CORE_TRACE("%sr%s(%s, %s[0x%03x]); /* [(0x%08x + 0x%03x) = 0x%08x](0x%08x) */",
		bit_l ? "ld" : "st", ss, rR_NAME(D), rR_NAME(N), offset, vR(N), offset, ea, vR(D));

	if(bit_l)
		soc_core_reg_set(core, rR(D), vR(D));
	else
		soc_core_write(core, ea, size, vR(D));
}

static void soc_core_thumb_ldst_rd_i(soc_core_p core)
{
	const uint16_t operation = mlBFTST(IR, 15, 12);
	const int bit_l = BEXT(IR, 11);
	const uint16_t imm8 = mlBFMOV(IR, 7, 0, 2);

	soc_core_decode_dst(core, rRD, 10, 8);

	switch(operation)
	{
		case	0x4000:
			_setup_rR_vR(N, rPC, THUMB_PC & ~0x03);
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

	const uint32_t ea = vR(N) + imm8;

	if(bit_l)
		vR(D) = soc_core_read(core, ea, sizeof(uint32_t));
	else
		vR(D) = soc_core_reg_get(core, rR(D));

	CORE_TRACE("%s(%s, %s[0x%03x]); /* [0x%08x](0x%08x) */",
		bit_l ? "ldr" : "str", rR_NAME(D), rR_NAME(N), imm8, ea, vR(D));

	if(bit_l)
		soc_core_reg_set(core, rR(D), vR(D));
	else
		soc_core_write(core, ea, sizeof(uint32_t), vR(D));
}

static void soc_core_thumb_ldst_rm_rn_rd(soc_core_p core)
{
//	struct {
		const int bit_l = BEXT(IR, 11) | (3 == mlBFEXT(IR, 10, 9));
		const uint8_t bwh = mlBFEXT(IR, 11, 9);
//	}bit;

	soc_core_decode_src(core, rRM, 8, 6);
	soc_core_decode_src(core, rRN, 5, 3);
	soc_core_decode_dst(core, rRD, 2, 0);

	const char *ss = "";
	size_t size = 0;

	switch(bwh)
	{
		case 0x00:
		case 0x04:
			size = sizeof(uint32_t);
		break;
		case 0x01:
		case 0x05:
		case 0x07:
			ss = ((7 == bwh) ? "sh" : "h");
			size = sizeof(uint16_t);
		break;
		case 0x02:
		case 0x03:
		case 0x06:
			ss = ((3 == bwh) ? "sb" : "b");
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

	switch(bwh) {
		case 0x03:
			vR(D) = (int8_t)vR(D);
			break;
		case 0x07:
			vR(D) = (int16_t)vR(D);
			break;
	}

	CORE_TRACE("%sr%s(%s, %s, %s); /* 0x%08x[0x%08x](0x%08x) = 0x%08x */",
		bit_l ? "ld" : "st", ss, rR_NAME(D), rR_NAME(N), rR_NAME(M), vR(N), vR(M), ea, vR(D));

	if(bit_l)
		soc_core_reg_set(core, rR(D), vR(D));
	else
		soc_core_write(core, ea, size, vR(D));
}

static void soc_core_thumb_ldstm_rn_rxx(soc_core_p core)
{
//	struct {
		const int bit_l = BEXT(IR, 11);
//	}bit;

	soc_core_decode_src(core, rRN, 10, 8);

	const uint8_t rlist = mlBFEXT(IR, 7, 0);

	const uint32_t start_address = vR(N);
	const uint32_t end_address = start_address + (__builtin_popcount(rlist) << 2) - 4;

	uint32_t ea = start_address;

	/* CP15_r1_Ubit == 0 */
	assert(0 == (ea & 3));

	char reglist[9] = "\0\0\0\0\0\0\0\0\0";

	for(int i = 0; i <= 7; i++)
	{
		const unsigned rxx = BEXT(rlist, i);
		reglist[i] = rxx ? ('0' + i) : '.';

		if(rxx)
		{
			uint32_t rxx_v = 0;
			CYCLE++;

			if(bit_l)
			{
				rxx_v = soc_core_read(core, ea, sizeof(uint32_t));
				soc_core_reg_set(core, i, rxx_v);
			}
			else
			{
				rxx_v = soc_core_reg_get(core, i);
				soc_core_write(core, ea, sizeof(uint32_t), rxx_v);
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
		bit_l ? "ld" : "st", rR_NAME(N),
		wb ? "!" : "", reglist, vR(N));
}

static void soc_core_thumb_pop_push(soc_core_p core)
{
	const csx_p csx = core->csx;

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

	if(CP15_reg1_AbitOrUbit && (0 != (start_address & 3))) {
		LOG("start_address = 0x%08x, 0x%08x", start_address, start_address & 3);
		soc_core_disasm_thumb(core, IP, IR);
		soc_core_exception(core, _EXCEPTION_DataAbort);
	}

	uint32_t ea = start_address & ~3;

	uint32_t rxx_v = 0;
	char reglist[9] = "\0\0\0\0\0\0\0\0\0";

	for(int i = 0; i <=7; i++)
	{
		const unsigned rxx = BEXT(rlist, i);
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
				soc_core_write(core, ea, sizeof(uint32_t), rxx_v);
			}
			ea += sizeof(uint32_t);
		}
	}

	CORE_T(const char *pclrs = bit_r ? (bit_l ? ", PC" : ", LR") : "");
	reglist[8] = 0;
	CORE_TRACE("%s(rSP, r{%s%s}); /* 0x%08x */", bit_l ? "pop" : "push", reglist, pclrs, sp_v);

	if(bit_r)
	{
		if(bit_l)
		{ /* pop */
			rxx_v = soc_core_read(core, ea, sizeof(uint32_t));
			if(_arm_version >= arm_v5t)
				soc_core_reg_set_pcx(core, rxx_v);
			else
				soc_core_reg_set(core, rPC, rxx_v);
		}
		else
		{ /* push */
			rxx_v = LR;
			soc_core_write(core, ea, sizeof(uint32_t), rxx_v);
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
	rR(SOP) = mlBFEXT(IR, 12, 11);
	_setup_rR_vR(S, ~0, mlBFEXT(IR, 10, 6));

	soc_core_decode_src(core, rRM, 5, 3);
	soc_core_decode_dst(core, rRD, 2, 0);

	__alubox_arm_shift_sop_immediate(core);
	soc_core_flags_nz(core, vR(SOP));
	__alubox_arm_shift_c(core);

	soc_core_reg_set(core, rR(D), vR(SOP));

	const char* sops = shift_op_string[0][rR(SOP)];

	CORE_TRACE("%ss(%s, %s, 0x%02x); /* %s(0x%08x, 0x%02x) = 0x%08x */",
		sops, rR_NAME(D), rR_NAME(M), vR(S),
		sops, vR(M), vR(S), vR(SOP));
}

static void soc_core_thumb_sdp_rms_rdn(soc_core_p core)
{
	const uint8_t operation = mlBFEXT(IR, 9, 8);

	soc_core_decode_src(core, rRM, 6, 3);
	_setup_rR_dst(core, rRD, mlBFEXT(IR, 2, 0) | BMOV(IR, 7, 3));
	_setup_rR_dst(core, rRN, rR(D));

	const alubox_fn _alubox_fn[4] = {
		[THUMB_SDP_OP_ADD] = _alubox_thumb_add,
		[THUMB_SDP_OP_CMP] = _alubox_thumb_cmps,
		[THUMB_SDP_OP_MOV] = _alubox_thumb_mov,
		[3] = _alubox_thumb_nop,
	};
	
	_alubox_fn[operation](core, &GPR(rR(D)));

	switch(operation)
	{
		case THUMB_SDP_OP_ADD:
			CORE_TRACE("add(%s, %s); /* 0x%08x + 0x%08x = 0x%08x */",
				rR_NAME(D), rR_NAME(M), vR(N), vR(M), vR(D));
			break;
		case THUMB_SDP_OP_CMP:
			CORE_TRACE("cmp(%s, %s); /* 0x%08x - 0x%08x = 0x%08x */",
				rR_NAME(D), rR_NAME(M), vR(N), vR(M), vR(D));
			break;
		case THUMB_SDP_OP_MOV:
			CORE_TRACE("mov(%s, %s); /* 0x%08x */",
				rR_NAME(D), rR_NAME(M), vR(D));
			break;
		default:
			LOG("operation = 0x%01x", operation);
			soc_core_disasm_thumb(core, IP, IR);
			LOG_ACTION(exit(1));
			break;
	}
}

/* **** */

static void soc_core_thumb_step_fail_decode(soc_core_p core)
{
	LOG("ir = 0x%04x, ir[15, 13] = 0x%02x", IR, mlBFTST(IR, 15, 13));

	soc_core_disasm_thumb(core, IP, IR);
	LOG_ACTION(exit(1));
}

static void soc_core_thumb_step_undefined(soc_core_p core)
{
	UNDEFINED;

	UNUSED(core);
}

static void soc_core_thumb_step_unimplimented(soc_core_p core)
{
	UNIMPLIMENTED;

	UNUSED(core);
}

static void soc_core_thumb_step_unpredictable(soc_core_p core)
{
	UNPREDICTABLE;

	UNUSED(core);
}

/* **** */

static void soc_core_thumb_step_group0_0000_1fff(soc_core_p core)
{
	switch(mlBFTST(IR, 15, 10)) {
		case 0x1800: /* 0001 10xx xxxx xxxx */
			return(soc_core_thumb_add_sub_rn_rd_rm(core));
		case 0x1c00: /* 0001 11xx xxxx xxxx */
			return(soc_core_thumb_add_sub_rn_rd_imm3(core));
		default:
			return(soc_core_thumb_sbi_imm5_rm_rd(core));
	}

	LOG_ACTION(soc_core_thumb_step_fail_decode(core));
}

static void soc_core_thumb_step_group2_4000_5fff(soc_core_p core)
{
	if(0x5000 == mlBFTST(IR, 15, 12)) { /* 0101 xxxx xxxx xxxx */
		return(soc_core_thumb_ldst_rm_rn_rd(core));
	} else if(0x4800 == mlBFTST(IR, 15, 11)) { /* 0100 1xxx xxxx xxxx */
		return(soc_core_thumb_ldst_rd_i(core));
	} else {
		switch(mlBFTST(IR, 15, 10)) {
			case 0x4000: /* 0100 00xx xxxx xxxx */
				return(soc_core_thumb_dp_rms_rdn(core));
			case 0x4400: /* 0100 01xx xxxx xxxx */
				switch(mlBFTST(IR, 15, 8)) {
					case 0x4700: /* 0100 0111 xxxx xxxx */
						return(soc_core_thumb_bx(core));
					default: /* 0100 01xx xxxx xxxx */
						return(soc_core_thumb_sdp_rms_rdn(core));
				}
				break;
		}
	}

	LOG_ACTION(soc_core_thumb_step_fail_decode(core));
}

static void soc_core_thumb_step_group5_b000_bfff(soc_core_p core)
{
	switch(mlBFTST(IR, 15, 8)) {
		case 0xb000: /* 1011 0000 xxxx xxxx */
			return(soc_core_thumb_add_sub_sp_i7(core));
		case 0xb400: /* 1011 0100 xxxx xxxx */
		case 0xb500: /* 1011 0101 xxxx xxxx */
		case 0xbc00: /* 1011 1100 xxxx xxxx */
		case 0xbd00: /* 1011 1101 xxxx xxxx */
			return(soc_core_thumb_pop_push(core));
	}

	LOG_ACTION(soc_core_thumb_step_fail_decode(core));
}

static void soc_core_thumb_step_group6_c000_dfff(soc_core_p core)
{
	if(BTST(IR, 12)) {
		switch(mlBFTST(IR, 15, 8)) {
			case 0xde00: /* 1101 1110 xxxx xxxx -- undefined */
				LOG_ACTION(return(soc_core_thumb_step_undefined(core)));
				return;
			case 0xdf00: /* 1101 1111 xxxx xxxx -- swi */
				LOG_ACTION(return(soc_core_thumb_step_unimplimented(core)));
				return;
			default: /* 1101 xxxx xxxx xxxx */
				return(soc_core_thumb_bcc(core));
		}
	} else { /* 1100 xxxx xxxx xxxx */
		return(soc_core_thumb_ldstm_rn_rxx(core));
	}

	LOG_ACTION(return(soc_core_thumb_step_fail_decode(core)));
}

static void soc_core_thumb_step_group7_e000_ffff(soc_core_p core)
{
	switch(mlBFTST(IR, 15, 11)) {
		case 0xe000: /* 1110 0xxx xxxx xxxx */
			return(soc_core_thumb_bxx_b(core));
		case 0xe800:
			if(IR & 1) { /* 1110 1xxx xxxx xxx1 */
				LOG_ACTION(return(soc_core_thumb_step_undefined(core)));
			} else /* 1110 1xxx xxxx xxx0 */
				return(soc_core_thumb_bxx_blx(core));
		case 0xf800:
			return(soc_core_thumb_bxx_bl(core));
		case 0xf000:
			return(soc_core_thumb_bxx_prefix(core));
	}

	LOG_ACTION(return(soc_core_thumb_step_fail_decode(core)));
}

/* **** */

void soc_core_thumb_step(soc_core_p core)
{
	CCx.e = 1;
	CORE_T(CCx.s = "AL");

	IR = soc_core_reg_pc_fetch_step_thumb(core);

	uint32_t group = mlBFTST(IR, 15, 13);
	switch(group) {
		case 0x0000: /* 000x xxxx xxxx xxxx */
			return(soc_core_thumb_step_group0_0000_1fff(core));
		case 0x2000: /* 001x xxxx xxxx xxxx */
			return(soc_core_thumb_ascm_rd_i(core));
		case 0x4000: /* 010x xxxx xxxx xxxx */
			return(soc_core_thumb_step_group2_4000_5fff(core));
		case 0x6000: /* 011x xxxx xxxx xxxx */
			return(soc_core_thumb_ldst_bwh_o_rn_rd(core));
		case 0x8000: /* 100x xxxx xxxx xxxx */
			if(BTST(IR, 12)) /* 1001 xxxx xxxx xxxx */
				return(soc_core_thumb_ldst_rd_i(core));
			else /* 1000 xxxx xxxx xxxx */
				return(soc_core_thumb_ldst_bwh_o_rn_rd(core));
			break;
		case 0xa000: /* 101x xxxx xxxx xxxx */
			if(BTST(IR, 12)) /* 1011 xxxx xxxx xxxx */
				return(soc_core_thumb_step_group5_b000_bfff(core));
			else /* 1010 xxxx xxxx xxxx */
				return(soc_core_thumb_add_rd_pcsp_i(core));
			break;
		case 0xc000: /* 110x xxxx xxxx xxxx */
			return(soc_core_thumb_step_group6_c000_dfff(core));
		case 0xe000: /* 111x xxxx xxxx xxxx */
			return(soc_core_thumb_step_group7_e000_ffff(core));
	}

	LOG_ACTION(return(soc_core_thumb_step_fail_decode(core)));
}

void soc_core_thumb_step_profile(soc_core_p core)
{
	const uint64_t dtime = _profile_soc_core_step_thumb ? get_dtime() : 0;

	soc_core_thumb_step(core);

	CSX_PROFILE_STAT_COUNT(soc_core.step.thumb, dtime);
}
