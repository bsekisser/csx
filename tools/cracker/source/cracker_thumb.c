#include "cracker_thumb.h"

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

static int thumb_add_sub_rn_rd(cracker_p cj)
{
	const int bit_i = BEXT(IR, 10);
	const uint8_t op2 = BEXT(IR, 9);
	const char* ops[2] = { "SUBS", "ADDS" };

	setup_rR_vR(D, mlBFEXT(IR, 2, 0), 0);
	setup_rR_vR(M, mlBFEXT(IR, 8, 6), 0);
	setup_rR_vR(N, mlBFEXT(IR, 5, 3), 0);

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

	switch(op) {
		case THUMB_ASCM_ADD:
		case THUMB_ASCM_CMP:
		case THUMB_ASCM_MOV:
		case THUMB_ASCM_SUB:
			CORE_TRACE("%s(%s, %02x)",
				opname[op], reg_name[rR(D)], imm8);
			break;
		default:
			CORE_TRACE("ASCM_OP = 0x%02x", op);
			LOG_ACTION(exit(-1));
			break;
	}
	
	return(1);
}

#define THUMB_BL_BLX_H mlBFEXT(IR, 12, 11)

static int thumb_bl_blx(cracker_p cj)
{
	int32_t eao = mlBFMOVs(IR, 10, 0, 12);
	uint32_t lr = 2 + (PC & ~1);

	if(0) CORE_TRACE("PC = 0x%08x, H = 0x%02x, eao = 0x%08x", PC, THUMB_BL_BLX_H, eao);

	switch(THUMB_BL_BLX_H) {
		case 0x2:
			lr += eao;
			break;
		default:
			CORE_TRACE("H = 0x%02x", THUMB_BL_BLX_H);
			return(0);
//			LOG_ACTION(exit(-1));
			break;
	}
	
	IR <<= 16;
	IR += _read(cj, PC & ~1, sizeof(uint16_t));
	PC += sizeof(uint16_t);

	eao += mlBFMOV(IR, 10, 0, 1);
	if(0) CORE_TRACE("PC = 0x%08x, H = 0x%02x, LR = 0x%08x, eao = 0x%08x", PC, THUMB_BL_BLX_H, lr, eao);

	uint32_t new_pc = lr + mlBFMOV(IR, 10, 0, 1);

	switch(THUMB_BL_BLX_H) {
		case 0x01:
			new_pc &= ~3;
			CORE_TRACE("BLX(0x%08x)", new_pc);
			break;
		case 0x03:
			new_pc |= 1;
			CORE_TRACE("BL(0x%08x)", new_pc & ~1);
			break;
		default:
			CORE_TRACE("H = 0x%02x, LR = 0x%08x, eao = 0x%08x", THUMB_BL_BLX_H, lr, eao);
			return(0);
//			LOG_ACTION(exit(-1));
			break;
	}

	cracker_text(cj, lr | 1);
	cracker_text(cj, new_pc);

	return(1);
}

static int thumb_ldst_rd_i(cracker_p cj)
{
	const int bit_l = BEXT(IR, 11);
	const uint16_t offset = mlBFMOV(IR, 7, 0, 2);

	rR(D) = mlBFEXT(IR, 10, 8);

	switch(mlBFTST(IR, 15, 12)) {
		case 0x4000: /* pc */
			setup_rR_vR(N, rPC, THUMB_PC);
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
		uint ea = vR(N) + offset;

		cracker_data(cj, ea, sizeof(uint32_t));

		uint32_t data = _read(cj, ea, sizeof(uint32_t));

		_CORE_TRACE_("); /* 0x%08x */", data);
	}

	CORE_TRACE_END();

	return(1);
}

static int thumb_ldstm(cracker_p cj)
{
	const int bit_l = BEXT(IR, 11);

	rR(N) = mlBFEXT(IR, 10, 8);

	char reglist[9], *dst = reglist;

	for(int i = 0; i <= 7; i++)
		*dst++ = BEXT(IR, i) ? ('0' + i) : '.';
	*dst = 0;

	CORE_TRACE("%sMIA(%s.WB, {%s})", bit_l ? "LD" : "ST",
		reg_name[rR(N)], reglist);

	return(1);
}

static int thumb_shift_i(cracker_p cj)
{
	const uint sop = mlBFEXT(IR, 12, 11);

	setup_rR_vR(D, mlBFEXT(IR, 2, 0), 0);
	setup_rR_vR(M, mlBFEXT(IR, 5, 3), 0);
	setup_rR_vR(S, ~0, mlBFEXT(IR, 10, 6));

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

static int thumb_sdp_rms_rdm(cracker_p cj)
{
	const uint8_t operation = mlBFEXT(IR, 9, 8);
	const char* _sos[] = { "ADD", "CMP", "MOV", 0 };
	const char* sos = _sos[operation];

	setup_rR_vR(D, mlBFEXT(IR, 2, 0) | BMOV(IR, 7, 3), 0);
	setup_rR_vR(M, mlBFEXT(IR, 6, 3), 0);

	if(!sos) {
		LOG("operation = 0x%01x", operation);
		LOG_ACTION(exit(1));
	}

	CORE_TRACE("%s(%s, %s)", sos, reg_name[rR(D)],
		reg_name[rR(M)]);

	return(1);
}

/* **** */

int thumb_step(cracker_p cj)
{
	IR = _fetch(cj);
	CCx = CC_AL;

	for(int ir_lsb = 8; ir_lsb <= 13; ir_lsb++) {
		uint32_t opcode = mlBFTST(IR, 15, ir_lsb);
		
		switch(opcode) {
			case 0x0000:
				return(thumb_shift_i(cj));
				break;
			case 0x1800:
				return(thumb_add_sub_rn_rd(cj));
				break;
			case 0x2000:
				return(thumb_ascm_i(cj));
				break;
			case 0x4400:
				return(thumb_sdp_rms_rdm(cj));
				break;
			case 0x4800:
			case 0x9000:
			case 0x9800:
				return(thumb_ldst_rd_i(cj));
				break;
			case 0xc000:
				return(thumb_ldstm(cj));
				break;
			case 0xe800:
				if(IR & 1)
					LOG_ACTION(exit(-1));
			case 0xf000:
				return(thumb_bl_blx(cj));
			default:
				if(0) CORE_TRACE("IR[15:13] = 0x%02x, opcode = 0x%08x",
					mlBFEXT(IR, 15, 13), opcode);
				break;
		}
	}

	CORE_TRACE_START("IR[15:13] = 0x%02x", mlBFEXT(IR, 15, 13));
	CORE_TRACE_END();

	LOG_ACTION(exit(-1));
}
