#include "cracker_thumb.h"

#include "cracker_arm_ir.h"
#include "cracker_enum.h"
#include "cracker_strings.h"
#include "cracker_trace.h"
#include "cracker.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

static int _fetch(cracker_p cj)
{
	PC += sizeof(uint16_t);
	
	return(_read(cj, IP & ~1, sizeof(uint16_t)));
}

/* **** */

static int thumb_add_rd_pcsp_i(cracker_p cj)
{
	const uint16_t imm8 = mlBFMOV(IR, 7, 0, 2);
	const int is_sp = BEXT(IR, 11);
	
	setup_rR_vR(N, is_sp ? rSP : rPC, is_sp ? 0 : THUMB_PC);
	
	setup_rR_vR(D, mlBFEXT(IR, 10, 8), 0);
	
	rR_SRC(D) = ~rR(N);

	CORE_TRACE_START();

	_CORE_TRACE_("ADD(%s, %s, 0x%03x)", rR_NAME(D), rR_NAME(N), imm8);

	if(rPC == xR_SRC(D)) {
		rR_GPR(D) = vR(N) + imm8;

		_CORE_TRACE_("; /* 0x%08x */", rR_GPR(D));
	}

	CORE_TRACE_END(")");

	return(1);
}

static int thumb_add_sub_rn_rd(cracker_p cj)
{
	const int bit_i = BEXT(IR, 10);
	const uint8_t op2 = BEXT(IR, 9);
	const char* ops[2] = { "SUBS", "ADDS" };

	setup_rR_vR(D, mlBFEXT(IR, 2, 0), 0);
	setup_rR_vR(M, mlBFEXT(IR, 8, 6), 0);
	setup_rR_vR(N, mlBFEXT(IR, 5, 3), 0);

	rR_SRC(D) = ~rR(N);

	if(bit_i)
	{
		CORE_TRACE("%s(%s, %s, 0x%01x)", ops[op2], reg_name[rR(D)],
			reg_name[rR(N)], rR(M));
	}
	else
	{
		CORE_TRACE("%s(%s, %s, %s)", ops[op2], reg_name[rR(D)],
			reg_name[rR(N)], reg_name[rR(M)]);
	}
	
	return(1);
}

static int thumb_add_sub_sp_i(cracker_p cj)
{
	const uint16_t imm7 = mlBFMOV(IR, 6, 0, 2);
	const int is_sub = BEXT(IR, 7);
	
	CORE_TRACE("%s(SP, 0x%03x)", is_sub ? "SUB" : "ADD", imm7);

	return(1);
}

enum {
	THUMB_ASCM_MOV,
	THUMB_ASCM_CMP,
	THUMB_ASCM_ADD,
	THUMB_ASCM_SUB,
};

static int thumb_ascm_i(cracker_p cj)
{
	const uint imm8 = mlBFEXT(IR, 7, 0);
	const uint op = mlBFEXT(IR, 12, 11);
	const char* opname[4] = { "MOVS", "CMPS", "ADDS", "SUBS" };

	setup_rR_vR(D, mlBFEXT(IR, 10, 8), 0);
	rR_SRC(D) = 0;

	switch(op) {
		case THUMB_ASCM_ADD:
		case THUMB_ASCM_CMP:
		case THUMB_ASCM_MOV:
		case THUMB_ASCM_SUB:
			CORE_TRACE("%s(%s, 0x%02x)",
				opname[op], reg_name[rR(D)], imm8);
			break;
		default:
			CORE_TRACE("ASCM_OP = 0x%02x", op);
			LOG_ACTION(exit(-1));
			break;
	}
	
	return(1);
}

//#define THUMB_BL_BLX_H mlBFEXT(IR, 12, 11)

static int thumb_bxx_b(cracker_p cj, int32_t eao)
{
	const uint32_t new_pc = PC + eao;

	CORE_TRACE("B(0x%08x); /* 0x%08x + 0x%03x*/", new_pc & ~1, PC, eao);

	cracker_text(cj, new_pc | 1);
	
	return(0);
}

static int thumb_bxx_blx(
	cracker_p cj,
	int32_t eao)
{
	const int blx = (0 == BEXT(IR, 12));

//	const uint32_t new_pc = ((LR + eao) & (blx ? ~3 : ~0)) | (blx ? 0 : 1);
	const uint32_t new_pc = ((LR + eao) & (blx ? ~3 : ~1)) | (blx ? 0 : 1);

	if(0) LOG("LR = 0x%08x, PC = 0x%08x", LR, new_pc);

	const uint32_t new_lr = PC | 1;

	CORE_TRACE("BL%s(0x%08x); /* 0x%08x + 0x%08x, LR = 0x%08x */",
		blx ? "X" : "", new_pc & ~1, PC, eao, new_lr & ~1);

	if(0) LOG("LR = 0x%08x, PC = 0x%08x", new_lr, new_pc);

	symbol_p slr = cracker_text(cj, new_lr);
	slr->pass++;

	cracker_text(cj, new_pc);
	
//	return(0);
	return(1);
}

static int thumb_bcc(cracker_p cj)
{
	CCv = mlBFEXT(IR, 11, 8);
	const int32_t imm8 = mlBFMOVs(IR, 7, 0, 1);

	const uint32_t new_pc = THUMB_PC + imm8;

	CORE_TRACE("B(0x%08x); /* 0x%08x + 0x%03x */", new_pc & ~1, THUMB_PC, imm8);

	cracker_text(cj, new_pc | 1);
	
	symbol_p slr = cracker_text(cj, PC | 1);
	slr->pass++;

	return(1);
}

static int thumb_bx_blx(cracker_p cj)
{
	const int link = BEXT(IR, 7);
	
	setup_rR_vR(M, mlBFEXT(IR, 6, 3), vR_GPR(M));
	
	CORE_TRACE_START();
	
	_CORE_TRACE_("B%sX(%s)", link ? "L" : "", rR_NAME(M));
	
	if(rPC == xR_SRC(M)) {
		_CORE_TRACE_("; /* 0x%08x */", vR(M));

		cracker_text(cj, vR(M));
	}

	CORE_TRACE_END();

	if(link) {
		symbol_p slr = cracker_text(cj, PC);
		slr->pass++;

		return(1);
	}

	return(0);
}

static int thumb_bxx(cracker_p cj)
{
	for(int i = 0; i < 2; i++) {
		int32_t eao = mlBFEXTs(IR, 10, 0);
		const uint8_t h = mlBFEXT(IR, 12, 11);

		if(0) CORE_TRACE("H = 0x%02x, LR = 0x%08x, PC = 0x%08x, EAO = 0x%08x",
			h, LR, PC, eao);

		switch(h) {
			case 0x00:
				/* branch offset is from PC + 4, ie.. lr */
				return(thumb_bxx_b(cj, eao << 1));
			case 0x01:
			case 0x03:
				eao = mlBFMOV(IR, 10, 0, 1);
				return(thumb_bxx_blx(cj, eao));
			case 0x02:
				eao <<= 12;
				LR = THUMB_PC + eao;

				IR <<= 16;
				IR += _read(cj, PC & ~1, sizeof(uint16_t));

				if((0x7 != mlBFEXT(IR, 15, 13)) && !BEXT(IR, 11)) {
					CORE_TRACE("/* xxx -- LR = 0x%08x + 0x%03x = 0x%08x */", PC, eao, LR);
					return(0);
				}

				PC += 2;

				break;
		}
	}
	
	CORE_TRACE("/* xxx!!!xxx -- PC = 0x%08x, LR = 0x%08x */", PC, LR);

	return(0);
}

static int thumb_dpr_rms_rdn(cracker_p cj)
{
	const char* _dpr_ops[16] = {
		"AND", "EOR", "LSL", "LSR", "ASR", "ADC", "SBC", "ROR",
		"TST", "RSB", "CMP", "CMN", "ORR", "MUL", "BIC", "MVN" };

	const uint operation = mlBFEXT(IR, 9, 6);
	const char* dpr_ops = _dpr_ops[operation];

	setup_rR_vR(D, mlBFEXT(IR, 2, 0), 0);
	setup_rR_vR(M, mlBFEXT(IR, 5, 3), 0);

	rR_SRC(D) = 0;
	
	CORE_TRACE("%s(%s, %s)", dpr_ops, rR_NAME(D), rR_NAME(M));

	return(1);
}

static int thumb_ldst_bwh_o_rn_rd(cracker_p cj)
{
	const int bit_h = BEXT(IR, 15);
	const int bit_b = BEXT(IR, 12);
	const int bit_l = BEXT(IR, 11);

	const uint8_t imm5 = mlBFEXT(IR, 10, 6);
	
	setup_rR_vR(D, mlBFEXT(IR, 2, 0), 0);
	setup_rR_vR(N, mlBFEXT(IR, 5, 3), 0);
	
	if(bit_l)
		rR_SRC(D) = 0;
	
	const char* bwh = (bit_h ? "H" : (bit_b ? "B" : ""));

	CORE_TRACE_START();

	_CORE_TRACE_("%sR%s(%s, %s", bit_l ? "LD" : "ST", bwh,
		rR_NAME(D), rR_NAME(N));

	if(imm5) {
		const uint offset = imm5 << (bit_h ? 1 : (bit_b ? 0 : 2));

		_CORE_TRACE_(", 0x%03x", offset);
	}

	CORE_TRACE_END(")");
	
	return(1);
}

static int thumb_ldst_rd_i(cracker_p cj)
{
	const int bit_l = BEXT(IR, 11);
	const uint16_t offset = mlBFMOV(IR, 7, 0, 2);

	setup_rR_vR(D, mlBFEXT(IR, 10, 8), 0);
	if(bit_l)
		rR_SRC(D) = 0;

	switch(mlBFTST(IR, 15, 12)) {
		case 0x4000: /* pc */
			setup_rR_vR(N, rPC, THUMB_PC & ~3);
			break;
		case 0x9000: /* sp */
			setup_rR_vR(N, rSP, 0);
			break;
		default:
			LOG_ACTION(exit(-1));
			break;
	}

	CORE_TRACE_START("%sR(%s, %s, 0x%04x", bit_l ? "LD" : "ST",
		reg_name[rR(D)], reg_name[rR(N)], offset);

	if(rPC == rR(N)) {
		const uint ea = vR(N) + offset;

		cracker_data(cj, ea, sizeof(uint32_t));

		const uint32_t data = _read(cj, ea, sizeof(uint32_t));

		_CORE_TRACE_("); /* 0x%08x */", data);
	}

	CORE_TRACE_END();

	return(1);
}

static int thumb_ldstm(cracker_p cj)
{
	const int bit_l = BEXT(IR, 11);

//	rR(N) = mlBFEXT(IR, 10, 8);
	setup_rR_vR(N, mlBFEXT(IR, 10, 8), 0);

	char reglist[9], *dst = reglist;

	for(int i = 0; i <= 7; i++)
		*dst++ = BEXT(IR, i) ? ('0' + i) : '.';
	*dst = 0;

	CORE_TRACE("%sMIA(%s.WB, {%s})", bit_l ? "LD" : "ST",
		reg_name[rR(N)], reglist);

	return(1);
}

static int thumb_ldst_op_rm_rn_rd(cracker_p cj)
{
	LOG_ACTION(exit(-1));
}

static int thumb_shift_i(cracker_p cj)
{
	const uint sop = mlBFEXT(IR, 12, 11);

	setup_rR_vR(D, mlBFEXT(IR, 2, 0), 0);
	setup_rR_vR(M, mlBFEXT(IR, 5, 3), 0);
	setup_rR_vR(S, ~0, mlBFEXT(IR, 10, 6));
	
	rR_SRC(D) = 0;

	switch(sop) {
		case SOP_ASR:
		case SOP_LSR:
			if(!vR(S))
				vR(S) = 32;
		case SOP_LSL:
		case SOP_ROR:
			break;
		default:
			CORE_TRACE("SHIFT_I_OP = 0x%02x", sop);
			LOG_ACTION(exit(-1));
			break;
	}

	CORE_TRACE("%s(%s, %s, 0x%02x)",
		shift_op_string[sop], reg_name[rR(D)],
		reg_name[rR(M)], vR(S));

	return(1);
}

static int thumb_pop_push(cracker_p cj)
{
	const int bit_l = BEXT(IR, 11);
	const int bit_r = BEXT(IR, 8);

	char reglist[9], *dst = reglist;

	for(int i = 0; i <= 7; i++)
		*dst++ = BEXT(IR, i) ? ('0' + i) : '.';
	*dst = 0;

	const char *pclrs = bit_r ? (bit_l ? ", PC" : ", LR") : "";
	CORE_TRACE("%s(rSP, r{%s%s});", bit_l ? "POP" : "PUSH", reglist, pclrs);

	return(!(bit_r && bit_l));
}

static int thumb_sdp_rms_rdn(cracker_p cj)
{
	const uint8_t operation = mlBFEXT(IR, 9, 8);
	if(0x03 == operation) { /* invalid */
		return(0);
	}

	const char* _sos[] = { "ADD", "CMP", "MOV", 0 };
	const char* sos = _sos[operation];

	setup_rR_vR(D, mlBFEXT(IR, 2, 0) | BMOV(IR, 7, 3), 0);
	setup_rR_vR(M, mlBFEXT(IR, 6, 3), 0);

	rR_SRC(D) = 0;

	CORE_TRACE("%s(%s, %s)", sos, reg_name[rR(D)],
		reg_name[rR(M)]);

	return(rPC != rR(D));
}

/* **** */

int thumb_step(cracker_p cj)
{
	IR = _fetch(cj);
	CCv = CC_AL;

	uint32_t opcode = 0;
	
	for(int ir_lsb = 8; ir_lsb <= 13; ir_lsb++) {
		opcode = mlBFTST(IR, 15, ir_lsb);
		
		switch(opcode) {
			case 0x0000:
				return(thumb_shift_i(cj));
				break;
			case 0x1800:
			case 0x1c00:
				return(thumb_add_sub_rn_rd(cj));
				break;
			case 0x2000:
				return(thumb_ascm_i(cj));
				break;
			case 0x4000:
				return(thumb_dpr_rms_rdn(cj));
			case 0x4400:
				return(thumb_sdp_rms_rdn(cj));
				break;
			case 0x4700: /* bx_blx */
				return(thumb_bx_blx(cj));
				break;
			case 0x5000:
				return(thumb_ldst_op_rm_rn_rd(cj));
				break;
			case 0x6000: /* str */
			case 0x6800: /* ldr */
			case 0x7000: /* strb */
			case 0x7100: /* ldrb */
			case 0x8000: /* strh */
			case 0x8100: /* ldrh */
				return(thumb_ldst_bwh_o_rn_rd(cj));
				break;
			case 0x4800: /* ldr rd, pc[offset8] */
			case 0x9000: /* str rd, sp[offset8] */
			case 0x9800: /* ldr rd, sp[offset8] */
				return(thumb_ldst_rd_i(cj));
				break;
			case 0xa000:
				return(thumb_add_rd_pcsp_i(cj));
				break;
			case 0xb000: /* miscelaneous */
				switch(mlBFTST(IR, 15, 8)) {
					case 0xb000:
						return(thumb_add_sub_sp_i(cj));
					break;
				}
				goto fail_decode;
				break;
			case 0xb400: /* push */
			case 0xbc00: /* pop */
				return(thumb_pop_push(cj));
				break;
			case 0xc000:
				return(thumb_ldstm(cj));
				break;
			case 0xd000: /* bcc */
				return(thumb_bcc(cj));
				break;
			case 0xde00: /* undefined instruction */
			case 0xdf00: /* swi */
				break;
			case 0xe800: /* blx suffix / undefined instruction */
				if(IR & 1) /* undefined instruction */
					return(0);
//					LOG_ACTION(exit(-1));
				__attribute__((fallthrough));
			case 0xe000: /* unconditional branch */
			case 0xf000: /* bl/blx prefix */
			case 0xf800: /* bl suffix */
//				return(thumb_bl_blx(cj));
				return(thumb_bxx(cj));
		}
	}

fail_decode:
	opcode = mlBFTST(IR, 15, 13);
	CORE_TRACE_START("IR[15:13] = 0x%02x", opcode);
	
	switch(opcode) {
		case 0xa000:
			_CORE_TRACE_(", IR[15:8] = 0x%02x", mlBFTST(IR, 15, 8));
			break;
	}
	
	CORE_TRACE_END();

	return(0);
//	LOG_ACTION(exit(-1));
}
