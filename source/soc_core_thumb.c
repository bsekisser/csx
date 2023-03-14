#define rRvRvPC PC_THUMB

#include "soc_core_thumb.h"
#include "soc_core_thumb_inst.h"

#include "soc_core_cp15.h"
#include "soc_core_disasm.h"
#include "soc_core_decode.h"
#include "soc_core_psr.h"
#include "soc_core_strings.h"
#include "soc_core_trace.h"
#include "soc_core_utility.h"

/* **** */

#include "bitfield.h"
#include "log.h"
#include "shift_roll.h"

/* **** */

#include "alu_box.h"

/* **** */
static void soc_core_thumb_add_rd_pcsp_i(soc_core_p core)
{
	const int pcsp = BEXT(IR, 11);
	
	if(pcsp)
		_setup_rR_vR(N, rSP, SP);
	else
		_setup_rR_vR(N, rPC, PC_THUMB & ~3);

	const uint16_t imm8 = mlBFMOV(IR, 7, 0, 2);

	_setup_rR_dst_rR_src(core, rRD, mlBFEXT(IR, 10, 8), rRN);

	vR(D) += imm8;

	CORE_TRACE("add(%s, %s, 0x%03x); /* 0x%08x + 0x%03x = 0x%08x */",
				rR_NAME(D), rR_NAME(N), imm8, vR(N), imm8, vR(D));

	soc_core_reg_set(core, rR(D), vR(D));
}

static void soc_core_thumb_add_sub_rn_rd(soc_core_p core)
{
	const int bit_i = BEXT(IR, 10);
	const uint8_t op2 = BEXT(IR, 9);

	if(bit_i)
		_setup_rR_vR(M, ~0, mlBFEXT(IR, 8, 6));
	else
		soc_core_decode_src(core, rRM, 8, 6);

	soc_core_decode_src(core, rRN, 5, 3);
	soc_core_decode_dst(core, rRD, 2, 0);

	alubox_fn _alubox_fn[2] = { _alubox_adds, _alubox_subs };

	vR(D) = _alubox_fn[op2](core, vR(N), vR(M));

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

	soc_core_reg_set(core, rR(D), vR(D));
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

	_setup_rR_vR(M, ~0, mlBFEXT(IR, 7, 0));
	soc_core_decode_src(core, rRN, 10, 8);

	alubox_fn _alubox_fn[4] = { _alubox_movs, _alubox_cmps, _alubox_adds, _alubox_subs };

	_setup_rR_vR(D, rR(N), _alubox_fn[operation](core, vR(N), vR(M)));

	const char* ops[4] = { "movs", "cmps", "adds", "subs" };
	const char opc[4] = { '=', '-', '+', '-' };

	switch(operation)
	{
		case THUMB_ASCM_OP_CMP:
			wb = 0;
			__attribute__((fallthrough));
		default:
			CORE_TRACE("%s(%s, 0x%03x); /* 0x%08x %c 0x%03x = 0x%08x */",
				ops[operation], rR_NAME(D),	vR(M),
					vR(N), opc[operation], vR(M), vR(D));
			break;
		case THUMB_ASCM_OP_MOV:
			CORE_TRACE("movs(%s, 0x%03x);", rR_NAME(D), vR(M));
			break;
	}

	if(wb)
		soc_core_reg_set(core, rR(D), vR(D));
}

static void soc_core_thumb_bcc(soc_core_p core)
{
	const uint8_t cond = mlBFEXT(IR, 11, 8);
	const int32_t imm8 = mlBFEXTs(IR, 7, 0) << 1;

	CCx.e = soc_core_check_cc(core, cond);

	const uint32_t new_pc = PC_THUMB + imm8;

	CORE_TRACE("b(0x%08x); /* 0x%08x + 0x%03x cce = 0x%08x */", new_pc & ~1, PC_THUMB, imm8, CCx.e);

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

	soc_core_decode_src(core, rRM, 6, 3);

	const int link = BEXT(IR, 7);

	const uint32_t new_pc = vR(M);
	const int thumb = new_pc & 1;

	CORE_TRACE("b%sx(%s); /* %c(0x%08x) */",
		link ? "l" : "", rR_NAME(M),
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
	const uint32_t new_pc = PC + eao;

	CORE_TRACE("b(0x%08x); /* 0x%08x + 0x%03x*/", new_pc & ~1, PC, eao);

	PC = new_pc;
}

static void soc_core_thumb_bxx_blx(
	soc_core_p core,
	int32_t eao)
{
	uint32_t new_pc = (LR + eao);

	if(0) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);

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

	if(0) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);
}

static void soc_core_thumb_bxx(soc_core_p core)
{
	for(int i = 0; i < 2; i++) {
		int32_t eao = mlBFEXTs(IR, 10, 0);
		const uint8_t h = mlBFEXT(IR, 12, 11);

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
				IR += soc_core_ifetch(core, PC & ~1, sizeof(uint16_t));

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

	alubox_fn _alubox_fn[16] = {
		_alubox_ands,	_alubox_eors,	_alubox_lsls,	_alubox_lsrs,
		_alubox_asrs,	_alubox_adcs,	_alubox_sbcs,	_alubox_rors,
		_alubox_tsts,	_alubox_rsbs,	_alubox_cmps,	_alubox_cmns,
		_alubox_orrs,	_alubox_muls,	_alubox_bics,	_alubox_mvns,
		};

	const char* _dpr_ops[2][16] = {{
		"ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
		"tsts", "rsbs", "cmps", "cmns", "orrs", "muls", "bics", "mvns",
		} , {
		"& ",	"^ ",	"<< ",	">> ",	"<<< ",	"+",	"-",	">><<",
		"& ",	"- ",	"- ",	"+ ",	"| ",	"* ",	"& ~",	"-",
		}};

	soc_core_decode_src(core, rRM, 5, 3);
	soc_core_decode_src(core, rRN, 2, 0);
	_setup_rR_vR(D, rR(N), _alubox_fn[operation](core, vR(N), vR(M)));

	int wb = 1;

	switch(operation)
	{
		case THUMB_DP_OP_CMP:
			wb = 0;
			__attribute__((fallthrough));
		default:
			CORE_TRACE("%s(%s, %s); /* 0x%08x %s0x%08x = 0x%08x */",
				_dpr_ops[0][operation], rR_NAME(D), rR_NAME(M),
				vR(N), _dpr_ops[1][operation], vR(M), vR(D));
			break;
		case THUMB_DP_OP_MVN:
			vR(D) = ~vR(M);
			CORE_TRACE("mvns(%s, %s); /* ~0x%08x = 0x%08x */",
				rR_NAME(D), rR_NAME(M), vR(M), vR(D));
			break;
	}

	if(wb)
		soc_core_reg_set(core, rR(D), vR(D));
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
		const uint rxx = BEXT(rlist, i);
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
		DataAbort();
	}

	uint32_t ea = start_address & ~3;

	uint32_t rxx_v = 0;
	char reglist[9] = "\0\0\0\0\0\0\0\0\0";

	for(int i = 0; i <=7; i++)
	{
		const uint rxx = BEXT(rlist, i);
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
	CORE_TRACE("%s(rSP, r{%s%s});", bit_l ? "pop" : "push", reglist, pclrs);

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
	const uint8_t operation = mlBFEXT(IR, 12, 11);
	const uint8_t imm5 = mlBFEXT(IR, 10, 6);

	soc_core_decode_src(core, rRM, 5, 3);
	soc_core_decode_dst(core, rRD, 2, 0);

	uint8_t shift = imm5;
	const char *sops = shift_op_string[0][operation];

	vR(D) = vR(M);

	switch(operation)
	{
		case THUMB_SBI_OP_ASR:
			if(shift)
			{
				BMAS(CPSR, SOC_CORE_PSR_BIT_C, BEXT(vR(M), (shift - 1)));
				vR(D) = _asr(vR(M), shift);
			}
			else
			{
				int rm31_c = BEXT(vR(M), 31);
				BMAS(CPSR, SOC_CORE_PSR_BIT_C, rm31_c);
				vR(D) = rm31_c ? ~0 : 0;
			}
			break;
		case THUMB_SBI_OP_LSL:
			if(shift)
			{
				BMAS(CPSR, SOC_CORE_PSR_BIT_C, BEXT(vR(M), (-shift & 31)));
				vR(D) = _lsl(vR(M), shift);
			}
			break;
		case THUMB_SBI_OP_LSR:
			if(shift)
				vR(D) = _lsr(vR(M), shift);
			else
				shift = 32;
			BMAS(CPSR, SOC_CORE_PSR_BIT_C, BEXT(vR(M), (shift - 1)));
			break;
		default:
			LOG("operation = 0x%01x", operation);
			LOG_ACTION(exit(1));
	}

	soc_core_flags_nz(core, vR(D));

	if(0) LOG("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & SOC_CORE_PSR_N), !!(CPSR & SOC_CORE_PSR_Z),
		!!(CPSR & SOC_CORE_PSR_C), !!(CPSR & SOC_CORE_PSR_V));

	CORE_TRACE("%ss(%s, %s, 0x%02x); /* %s(0x%08x, 0x%02x) = 0x%08x */",
		sops, rR_NAME(D), rR_NAME(M), shift,
		sops, vR(M), shift, vR(D));

	soc_core_reg_set(core, rR(D), vR(D));
}

static void soc_core_thumb_sdp_rms_rdn(soc_core_p core)
{
	const uint8_t operation = mlBFEXT(IR, 9, 8);

	soc_core_decode_src(core, rRM, 6, 3);
	_setup_rR_vR_src(core, rRD, mlBFEXT(IR, 2, 0) | BMOV(IR, 7, 3));

	uint32_t res = vR(D);

	switch(operation)
	{
		case THUMB_SDP_OP_ADD:
			res += vR(M);
			CORE_TRACE("add(%s, %s); /* 0x%08x + 0x%08x = 0x%08x */",
				rR_NAME(D), rR_NAME(M), vR(D), vR(M), res);
			break;
		case THUMB_SDP_OP_MOV:
			res = vR(M);
			CORE_TRACE("mov(%s, %s); /* 0x%08x */",
				rR_NAME(D), rR_NAME(M), res);
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

static void soc_core_thumb_step_0xe800(soc_core_p core)
{
	if(IR & 1)
		UNDEFINED;

	return(soc_core_thumb_bxx(core));
}

static void soc_core_thumb_step_fail_decode(soc_core_p core)
{
	LOG("ir = 0x%04x", IR);

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

typedef void (*thumb_fn)(soc_core_p core);

static void soc_core_thumb_step_0xb600(soc_core_p core)
{
	thumb_fn xb600[0x100] = {
		[0x40 ... 0x40] = soc_core_thumb_step_unpredictable, /* unpredictable */
		[0x50 ... 0x50] = soc_core_thumb_step_unimplimented, /* set endianness */
		[0x60 ... 0x67] = soc_core_thumb_step_unimplimented, /* change processor state */
		[0x68 ... 0x6f] = soc_core_thumb_step_unpredictable, /* unpredictable */
		[0x70 ... 0x77] = soc_core_thumb_step_unimplimented, /* change processor state */
		[0x78 ... 0x7f] = soc_core_thumb_step_unpredictable, /* unpredictable */
	};

	thumb_fn fn = xb600[IR & 0xff];
	if(fn)
		return(fn(core));

	return(soc_core_thumb_step_fail_decode(core));
}

static void soc_core_thumb_step_0xba00(soc_core_p core)
{
	thumb_fn xba00[0x100] = {
		[0x00 ... 0x70] = soc_core_thumb_step_unimplimented, /* reverse bytes */
		[0x80 ... 0xb0] = soc_core_thumb_step_undefined,
		[0xc0 ... 0xf0] = soc_core_thumb_step_unimplimented, /* reverse bytes */
	};

	thumb_fn fn = xba00[IR & 0xff];
	if(fn)
		return(fn(core));

	return(soc_core_thumb_step_fail_decode(core));
}

static thumb_fn thumb_fn_list_x000[0x100] = {
	[0x00 ... 0x17] = soc_core_thumb_sbi_imm5_rm_rd,
	[0x18 ... 0x1b] = soc_core_thumb_add_sub_rn_rd,
	[0x1c ... 0x1f] = soc_core_thumb_add_sub_rn_rd,
	[0x20 ... 0x3f] = soc_core_thumb_ascm_rd_i,
	[0x40 ... 0x43] = soc_core_thumb_dp_rms_rdn,
	[0x44 ... 0x46] = soc_core_thumb_sdp_rms_rdn,
	[0x47 ... 0x47] = soc_core_thumb_bx,
	[0x48 ... 0x4f] = soc_core_thumb_ldst_rd_i,
	[0x50 ... 0x5f] = soc_core_thumb_ldst_rm_rn_rd,
	[0x60 ... 0x7f] = soc_core_thumb_ldst_bwh_o_rn_rd,
	[0x80 ... 0x8f] = soc_core_thumb_ldst_bwh_o_rn_rd,
	[0x90 ... 0x9f] = soc_core_thumb_ldst_rd_i,
	[0xa0 ... 0xaf] = soc_core_thumb_add_rd_pcsp_i,
	[0xb0 ... 0xb0] = soc_core_thumb_add_sub_sp_i7,
	[0xb1 ... 0xb1] = soc_core_thumb_step_undefined,
	[0xb2 ... 0xb2] = soc_core_thumb_step_unimplimented, /* sign / zero extend */
	[0xb3 ... 0xb3] = soc_core_thumb_step_undefined,
	[0xb4 ... 0xb5] = soc_core_thumb_pop_push,
	[0xb6 ... 0xb6] = soc_core_thumb_step_0xb600,
	[0xb7 ... 0xb7] = soc_core_thumb_step_undefined,
	[0xb8 ... 0xb9] = soc_core_thumb_step_undefined,
	[0xba ... 0xba] = soc_core_thumb_step_0xba00,
	[0xbb ... 0xbb] = soc_core_thumb_step_undefined,
	[0xbc ... 0xbd] = soc_core_thumb_pop_push,
	[0xbe ... 0xbe] = soc_core_thumb_step_unimplimented, /* software breakpoint */
	[0xbf ... 0xbf] = soc_core_thumb_step_undefined,
	[0xc0 ... 0xcf] = soc_core_thumb_ldstm_rn_rxx,
	[0xd0 ... 0xdd] = soc_core_thumb_bcc,
	[0xde ... 0xde] = soc_core_thumb_step_undefined, /* undefined instruction */
	[0xdf ... 0xdf] = soc_core_thumb_step_unimplimented, /* swi */
	[0xe0 ... 0xe7] = soc_core_thumb_bxx,
	[0xe8 ... 0xef] = soc_core_thumb_step_0xe800,
	[0xf0 ... 0xf7] = soc_core_thumb_bxx,
	[0xf8 ... 0xff] = soc_core_thumb_bxx,
};

void soc_core_thumb_step(soc_core_p core)
{
	CCx.e = 1;
	CORE_T(CCx.s = "AL");

	IR = soc_core_reg_pc_fetch_step_thumb(core);

	thumb_fn fn = thumb_fn_list_x000[IR >> 8];

	if(fn) {
		return(fn(core));
	} else
		goto fail_decode;

	switch(IR)
	{
	/* **** */
		case 0x0000 ... (0x1000 | mlBF(10, 0)):
			if(SOC_CORE_THUMB_SBI_IMM5_RM_RD == (IR & SOC_CORE_THUMB_SBI_IMM5_RM_RD_MASK))
				return(soc_core_thumb_sbi_imm5_rm_rd(core));
			break;
		case 0x1800 ... (0x1800 | mlBF(9, 0)):
		case 0x1c00 ... (0x1c00 | mlBF(9, 0)):
			if(SOC_CORE_THUMB_ADD_SUB_RN_RD == (IR & SOC_CORE_THUMB_ADD_SUB_RN_RD_MASK))
				return(soc_core_thumb_add_sub_rn_rd(core));
			break;
		case 0x2000 ... (0x2000 | mlBF(12, 0)):
			if(SOC_CORE_THUMB_ASCM_RD_I8(0) == (IR & SOC_CORE_THUMB_ASCM_RD_I8_MASK))
				return(soc_core_thumb_ascm_rd_i(core));
			break;
		case 0x4000 ... (0x4000 | mlBF(9, 0)):
			if(SOC_CORE_THUMB_DP_RMS_RDN == (IR & SOC_CORE_THUMB_DP_RMS_RDN_MASK))
				return(soc_core_thumb_dp_rms_rdn(core));
			break;
		case 0x4400 ... (0x4600 | mlBF(7, 0)):
			if(SOC_CORE_THUMB_SDP_RMS_RDN(0) == (IR & SOC_CORE_THUMB_SDP_RMS_RDN_MASK))
				return(soc_core_thumb_sdp_rms_rdn(core));
			break;
		case 0x4700 ... (0x4700 | mlBF(7, 0)): /* bx_blx */
			if(SOC_CORE_THUMB_BX == (IR & SOC_CORE_THUMB_BX_MASK))
				return(soc_core_thumb_bx(core));
			break;
		case 0x4800 ... (0x4800 | mlBF(10, 0)): /* ldr rd, pc[offset8] */
		case 0x9000 ... (0x9000 | mlBF(11, 0)): /* str rd, sp[offset8] */
			if((SOC_CORE_THUMB_LDST_PC_RD_I == (IR & SOC_CORE_THUMB_LDST_PC_RD_I_MASK))
				|| (SOC_CORE_THUMB_LDST_SP_RD_I == (IR & SOC_CORE_THUMB_LDST_SP_RD_I_MASK)))
					return(soc_core_thumb_ldst_rd_i(core));
			break;
		case 0x5000 ... (0x5000 | mlBF(11, 0)): /* [ld|st]r[b|h|sb|sh] rd, [rn, rm] */
			if(SOC_CORE_THUMB_LDST_RM_RN_RD == (IR & SOC_CORE_THUMB_LDST_RM_RN_RD_MASK))
				return(soc_core_thumb_ldst_rm_rn_rd(core));
			break;
		case 0x6000 ... (0x6000 | mlBF(12, 0)): /* str */
		case 0x8000 ... (0x8000 | mlBF(11, 0)): /* strh */
			if((SOC_CORE_THUMB_LDST_BW_O_RN_RD == (IR & SOC_CORE_THUMB_LDST_BW_O_RN_RD_MASK))
				|| (SOC_CORE_THUMB_LDST_H_O_RN_RD == (IR & SOC_CORE_THUMB_LDST_H_O_RN_RD_MASK)))
					return(soc_core_thumb_ldst_bwh_o_rn_rd(core));
			break;
		case 0xa000 ... (0xa000 | mlBF(11, 0)):
			if(SOC_CORE_THUMB_ADD_RD_PCSP_I == (IR & SOC_CORE_THUMB_ADD_RD_PCSP_I_MASK))
				return(soc_core_thumb_add_rd_pcsp_i(core));
			break;
		case 0xb000 ... (0xb000 | mlBF(11, 0)): /* miscelaneous */
		{	switch(IR) {
				case 0xb000 ... (0xb000 | mlBF(7, 0)): /* adjust stack pointer */
					if(SOC_CORE_THUMB_ADD_SUB_SP_I7 == (IR & SOC_CORE_THUMB_ADD_SUB_SP_I7_MASK))
						return(soc_core_thumb_add_sub_sp_i7(core));
					break;
				case 0xb100 ... 0xb1ff:
				case 0xb300 ... 0xb3ff:
				case 0xb700 ... 0xb7ff:
				case 0xb800 ... 0xb9ff:
//				case 0xba80 ... (0xba80 | mlBF(5, 0)):
				case 0xbb00 ... 0xbbff:
				case 0xbf00 ... 0xbfff:
					UNDEFINED;
					break;
				case 0xb200 ... (0xb200 | mlBF(7, 0)): /* sign / zero extend */
				case 0xb650 ... 0xb65f: /* set endianness */
				case 0xb660 ... 0xb667: /* change processor state */
				case 0xb670 ... 0xb677: /* change processor state */
				case 0xba00 ... (0xba00 | mlBF(7, 0)): /* reverse bytes */
				case 0xbe00 ... (0xbe00 | mlBF(7, 0)): /* software breakpoint */
					UNIMPLIMENTED;
					break;
				case 0xb640 ... 0xb64f: /* unpredictable */
				case 0xb668 ... 0xb66f: /* unpredictable */
				case 0xb678 ... 0xb67f: /* unpredictable */
					UNPREDICTABLE;
					break;
				case 0xb400 ... (0xb400 | mlBF(8, 0)):
				case 0xbc00 ... (0xbc00 | mlBF(8, 0)):
					if(SOC_CORE_THUMB_POP_PUSH(0) == (IR & SOC_CORE_THUMB_POP_PUSH_MASK))
						return(soc_core_thumb_pop_push(core));
					break;
				}
		}	break;
		case 0xc000 ... (0xc000 | mlBF(11, 0)):
			if(SOC_CORE_THUMB_LDSTM_RN_RXX(0) == (IR & SOC_CORE_THUMB_LDSTM_RN_RXX_MASK))
				return(soc_core_thumb_ldstm_rn_rxx(core));
			break;
		case 0xd000 ... (0xdd00 | mlBF(7, 0)): /* bcc */
			return(soc_core_thumb_bcc(core));
			break;
		case 0xde00 ... (0xde00 | mlBF(7, 0)): /* undefined instruction */
			UNDEFINED;
			break;
		case 0xdf00 ... (0xdf00 | mlBF(7, 0)): /* swi */
			UNIMPLIMENTED;
			break;
		case 0xe800 ... (0xe800 | mlBF(10, 0)): /* blx suffix / undefined instruction */
			if(IR & 1)
				UNDEFINED;
			__attribute__((fallthrough));
		case 0xe000 ... (0xe000 | mlBF(10, 0)): /* unconditional branch */
		case 0xf000 ... (0xf000 | mlBF(10, 0)): /* bl/blx prefix */
		case 0xf800 ... (0xf800 | mlBF(10, 0)): /* bl suffix */
				return(soc_core_thumb_bxx(core));
			break;
	/* **** */
	}

fail_decode:
	LOG("IR = 0x%04x, IR[15:8] = 0x%04x", IR, mlBFTST(IR, 15, 8));

	soc_core_disasm_thumb(core, IP, IR);
	LOG_ACTION(exit(1));
}

void soc_core_thumb_step_profile(soc_core_p core)
{
	const uint64_t dtime = _profile_soc_core_step_thumb ? get_dtime() : 0;

	soc_core_thumb_step(core);

	CSX_PROFILE_STAT_COUNT(soc_core.step.thumb, dtime);
}
