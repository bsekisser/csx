#include "cracker_arm.h"
#include "cracker_arm_enum.h"
#include "cracker_arm_ir.h"
#include "cracker_enum.h"
#include "cracker_strings.h"
#include "cracker_trace.h"
#include "cracker.h"

/* **** */

#include "bitfield.h"
#include "shift_roll.h"
#include "log.h"

/* **** */

#include <assert.h>
#include <stdio.h>

/* **** */

static uint32_t _fetch(cracker_p cj)
{
	PC += sizeof(uint32_t);

	return(_read(cj, IP, sizeof(uint32_t)));
}

/* **** */

static int arm_b_bl(cracker_p cj)
{
	int link = BEXT(IR, 24);
	int32_t offset = mlBFEXTs(IR, 23, 0) << 2;

	uint32_t new_pc = ARM_PC + offset;

	CORE_TRACE("B%s%s(0x%08x)", link ? "L" : "", CCs(0), new_pc);
	
	if(link)
		cracker_text(cj, PC);

	cracker_text(cj, new_pc);
	
	if(CC_AL == CCx)
		PC = new_pc;
	
	return(1);
}

static int arm_bxt(cracker_p cj)
{
	assert(0xf == mlBFEXT(IR, 19, 16));
	assert(0xf == mlBFEXT(IR, 15, 12));
	assert(0xf == mlBFEXT(IR, 11, 8));

	setup_rR_vR(M, ARM_IR_RM, vR_GPR(M));

	CORE_TRACE("BX%s(%s)", CCs(0), rR_NAME(M));
	
	if(rPC == rR_SRC(M)) {
		PC = vR(M);
		return(1);
	}
		
	return(0);
}

static void arm_dpi(cracker_p cj)
{
	setup_rR_vR(D, ARM_IR_RD, 0);
	setup_rR_vR(N, ARM_IR_RN, vR_GPR(N));

	rR_SRC(D) = rR(N);

	CORE_TRACE_START();

	switch(ARM_DPI_OP) {
		case ARM_ADC:
		case ARM_ADD:
		case ARM_AND:
		case ARM_BIC:
		case ARM_EOR:
		case ARM_ORR:
		case ARM_RSB:
		case ARM_RSC:
		case ARM_SBC:
		case ARM_SUB:
			_CORE_TRACE_("%s%s%s(%s, %s, ",
				dpi_op_string[ARM_DPI_OP], CCs(0), ARM_DPI_S ? "S" : "",
				rR_NAME(D), rR_NAME(N));
			break;
		case ARM_CMP:
		case ARM_CMN:
		case ARM_TEQ:
		case ARM_TST:
			_CORE_TRACE_("%s%s(%s, ",
				dpi_op_string[ARM_DPI_OP], CCs(0),
				rR_NAME(N));
			break;
		case ARM_MOV:
		case ARM_MVN:
			assert(0 == mlBFEXT(IR, 19, 16));
			_CORE_TRACE_("%s%s%s(%s, ",
				dpi_op_string[ARM_DPI_OP], CCs(0), ARM_DPI_S ? "S" : "",
				rR_NAME(D));
			break;
		default:
			CORE_TRACE_END("0x%02x, %s", ARM_DPI_OP, dpi_op_string[ARM_DPI_OP]);
			LOG_ACTION(exit(-1));
			break;
	}

	if(CC_AL == CCx)
	{
		int wb = 1;

		switch(ARM_DPI_OP) {
			case ARM_ADD:
				if((rPC == rR(N)) && ARM_DPI_I)
					vR(D) = (4 + vR(N)) + vR(M);
				cracker_text(cj, vR(D));
				break;
			case ARM_MOV:
				if(rPC == rR(M))
					vR(D) = vR(M);
				cracker_text(cj, vR(D));
				break;
			default:
				wb = 0;
				break;
		}

		if(wb)
			rR_GPR(D) = vR(D);
	}
}

static int arm_dpi_i(cracker_p cj)
{
	uint shift = mlBFEXT(IR, 11, 8);
	uint imm8 = mlBFEXT(IR, 7, 0);

	setup_rR_vR(M, ARM_IR_RM, _ror(imm8, shift));

	arm_dpi(cj);

	if(shift) {
		CORE_TRACE_END("ROR(0x%02x, 0x%02x); /* 0x%08x */", imm8, shift, vR(M));
	} else {
		_CORE_TRACE_("0x%02x)", imm8);
		if(rPC == rR_SRC(D)) {
			CORE_TRACE_END("; /* 0x%08x */", vR(D));
		} else {
			CORE_TRACE_END();
		}
	}
	
	return(rPC != ARM_IR_RD);
}

static int arm_dpi_rs(cracker_p cj) {
	arm_dpi(cj);
	
	setup_rR_vR(M, ARM_IR_RM, 0);
	setup_rR_vR(S, ARM_IR_RS, 0);
	
	CORE_TRACE_END("%s(%s, %s))",
		shift_op_string[ARM_DPI_SOP],
		rR_NAME(M), rR_NAME(S));
	
	return(rPC != ARM_IR_RD);
}

static int arm_dpi_s(cracker_p cj) {
	uint shift = mlBFEXT(IR, 11, 7);

	setup_rR_vR(M, ARM_IR_RM, 0);

	switch(ARM_DPI_SOP) {
		case SOP_ASR:
		case SOP_LSR:
			if(0 == shift)
				shift = 32;
			break;
	}

	arm_dpi(cj);
	
	if(shift) {
		CORE_TRACE_END("%s(%s, 0x%02x))",
			shift_op_string[ARM_DPI_SOP],
			rR_NAME(M), shift);
	} else {
		if(SOP_ROR == ARM_DPI_SOP) {
			CORE_TRACE_END("RRX(%s))", rR_NAME(M));
		} else {
			CORE_TRACE_END("%s)", rR_NAME(M));
		}
	}
	
	return(rPC != ARM_IR_RD);
}

static void arm_ldst(cracker_p cj)
{
	setup_rR_vR(D, ARM_IR_RD, 0);
	setup_rR_vR(N, ARM_IR_RN, 0);

	CORE_TRACE_START();
	
	/* ldr|str{cond}{b}{t} <rd>, <addressing_mode> */
	/* ldr|str{cond}{h|sh|sb|d} <rd>, <addressing_mode> */

	int ldst_t = !ARM_LDST_P && ARM_LDST_W;

	switch(mlBFEXT(IR, 27, 25)) {
		case 0x00: { /* miscellaneous load/store */
			int ldst_l = ARM_LDST_L || (!ARM_LDST_L && !ARM_LDST_H);
			
			_CORE_TRACE_("%sR%s", ldst_l ? "LD" : "ST", CCs(0));
			_CORE_TRACE_("%s", ARM_LDST_FLAG_S ? "S" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_H ? "H" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_B ? "B" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_D ? "D" : "");
		}break;
		case 0x02: { /* default load store */
			_CORE_TRACE_("%sR%s", ARM_LDST_L ? "LD" : "ST", CCs(0));
			_CORE_TRACE_("%s%s", ARM_LDST_B ? "B" : "", ldst_t ? "T" : "");
		}break;
	}

	_CORE_TRACE_("(%s, ", rR_NAME(D));
}

static int arm_ldst_i(cracker_p cj)
{
	arm_ldst(cj);
	
	int32_t offset = mlBFEXT(IR, 11, 0);
	
	int wb = !ARM_LDST_P || (ARM_LDST_P && ARM_LDST_W);
	
	_CORE_TRACE_("%s%s, %s0x%04x", rR_NAME(N),
		wb ? " | rWB" : "", ARM_LDST_U ? "" : "-", offset);
	
	_CORE_TRACE_(")");

	if(rPC == rR(N)) {
		if(!ARM_LDST_U)
			offset = ~offset;

		uint32_t pat = ARM_PC + offset;
		size_t size = ARM_LDST_B ? sizeof(uint8_t) : sizeof(uint32_t);

		uint32_t data = _read(cj, pat, size);

		cracker_data(cj, pat, size);

		if(ARM_LDST_B) {
			_CORE_TRACE_("; /* [0x%08x]:0x%02x */", pat, data);
		} else {
			_CORE_TRACE_("; /* [0x%08x]:0x%08x */", pat, data);
		}
	}

	CORE_TRACE_END();
	
	return(rPC != ARM_IR_RD);
}


static int arm_ldst_sh(cracker_p cj)
{
	arm_ldst(cj);
	
	int wb = !ARM_LDST_P || (ARM_LDST_P && ARM_LDST_W);

	if(ARM_LDST_I22) {
		uint8_t offset = mlBFMOV(IR, 11, 8, 4) | mlBFEXT(IR, 3, 0);

		_CORE_TRACE_("%s%s, %s0x%04x", rR_NAME(N),
			wb ? " | rWB" : "", ARM_LDST_U ? "" : "-", offset);
	} else {
		assert(0 == mlBFEXT(IR, 11, 8));
		
		_CORE_TRACE_("%s%s, %s%s", rR_NAME(N),
			wb ? " | rWB" : "", ARM_LDST_U ? "" : "-", rR_NAME(M));
	}
	
	CORE_TRACE_END(")");
	
	return(rPC != ARM_IR_RD);
}

static int arm_ldstm(cracker_p cj)
{
	setup_rR_vR(N, ARM_IR_RN, 0);

	CORE_TRACE_START("%sM%s", ARM_LDST_L ? "LD" : "ST", CCs(0));
	_CORE_TRACE_("%c%c", ARM_LDST_U ? 'I' : 'D', ARM_LDST_P ? 'B' : 'A');
	_CORE_TRACE_("(%s%s, ", rR_NAME(N), ARM_LDST_W ? ".WB" : "");
	
	char reglist[17], *dst = reglist;
	
	for(int i = 0; i < 16; i++) {
		if(BEXT(IR, i))
			*dst++ = (i < 9 ? '0' : ('a' - 9)) + i;
		else
			*dst++ = '.';
	}

	*dst = 0;

	CORE_TRACE_END("{%s}%s)", reglist, ARM_LDSTM_S ? ".S" : "");
	
	return(!(BEXT(IR, PC) && (CC_AL == CCx)));
}

static int arm_mcr_mrc(cracker_p cj)
{
	int is_mrc = BEXT(IR, 20);

	setup_rR_vR(D, ARM_IR_RD, 0);

	CORE_TRACE_START();
	
	_CORE_TRACE_("M%s%s(CP%u, %u, %s, CRn(%u), CRm(%u)",
		is_mrc ? "CR" : "RC", CCs(0),
		mlBFEXT(IR, 11, 8), mlBFEXT(IR, 23, 21), rR_NAME(D),
		mlBFEXT(IR, 19, 16), mlBFEXT(IR, 3, 0));
	
	uint op2 = mlBFEXT(IR, 7, 5);

	if(op2) {
		_CORE_TRACE_(", %u)", op2);
	}
	
	CORE_TRACE_END();
	
	return(rPC != ARM_IR_RD);
}

static int arm_mrs(cracker_p cj)
{
	assert(0xf == mlBFEXT(IR, 19, 16));
	assert(0 == mlBFEXT(IR, 11, 0));

	setup_rR_vR(D, ARM_IR_RD, 0);

	int bit_r = BEXT(IR, 22);

	CORE_TRACE("MRS%s(%s, %cPSR)",
		CCs(0),
		rR_NAME(D), bit_r ? 'S' : 'C');

	return(1);
}

static int arm_msr(cracker_p cj)
{
	assert(0x0f == mlBFEXT(IR, 15, 12));

	CORE_TRACE_START();

	int bit_r = BEXT(IR, 22);

	const char psr_fields[5] = {
		BEXT(IR, 16) ? 'C' : 'c',
		BEXT(IR, 17) ? 'X' : 'x',
		BEXT(IR, 18) ? 'S' : 's',
		BEXT(IR, 19) ? 'F' : 'f',
		0,
	};

	if(BEXT(IR, 25)) {
		_CORE_TRACE_("MSR%s(%cPSR_%s, ",
			CCs(0),
			bit_r ? 'S' : 'C',
			psr_fields);

		uint imm8 = mlBFEXT(IR, 7, 0);
		uint shift = mlBFEXT(IR, 11, 8) << 1;
		
		if(shift) {
			_CORE_TRACE_("ROR(%02u, %03u)", shift, imm8);
		} else {
			_CORE_TRACE_("%03u", imm8);
		}
		
	} else {
		setup_rR_vR(M, ARM_IR_RM, 0);

		if(0 != mlBFEXT(IR, 11, 8)) {
			CORE_TRACE_END();
			LOG_ACTION(exit(-1));
		}

		_CORE_TRACE_("MSR%s(%cPSR_%s, %s",
			CCs(0),
			bit_r ? 'S' : 'C',
			psr_fields,
			rR_NAME(M));
	}

	CORE_TRACE_END(")");

	return(1);
}

/* **** */

const uint32_t _arm_inst0_0_i74 = _BV(7) | _BV(4);
const uint32_t _arm_inst0_0_misc = _BV(24);
const uint32_t _arm_inst0_0_misc_mask = mlBF(27, 23) | _BV(20);

const uint32_t _arm_inst0_1_bxt = _BV(24) | _BV(21) | _BV(4);
const uint32_t _arm_inst0_1_mask = (mlBF(27, 20) & (~_BV(22))) | mlBF(7, 4);
const uint32_t _arm_inst0_1_mrs = _BV(24);
const uint32_t _arm_inst0_1_msr = _BV(24) | _BV(21);

const uint32_t _arm_inst1_mask = mlBF(27, 20) & (~_BV(22));
const uint32_t _arm_inst1_mi2sr = mlBF(25, 24) | _BV(21);
const uint32_t _arm_inst1_undefined = mlBF(25, 24);

//const uint32_t _arm_inst7_cdp = mlBF(27, 25);
const uint32_t _arm_inst7_mcr_mrc = mlBF(27, 25) | _BV(4);
const uint32_t _arm_inst7_mask = mlBF(27, 24) | _BV(4);

int arm_step(cracker_p cj)
{
	IR = _fetch(cj);
	CCx = mlBFEXT(IR, 31, 28);

	uint ir_27_25 = mlBFEXT(IR, 27, 25);

	if(0xf != CCx) switch(ir_27_25) {
		case 0x00:
			if(_arm_inst0_0_i74 == (IR & _arm_inst0_0_i74)) {
				if(0 != mlBFEXT(IR, 6, 5))
					return(arm_ldst_sh(cj));
			} else if(_arm_inst0_0_misc != (IR & _arm_inst0_0_misc_mask)) {
				if(BEXT(IR, 4))
					return(arm_dpi_rs(cj));
				else
					return(arm_dpi_s(cj));
			} else {
				switch(IR & _arm_inst0_1_mask) {
					case _arm_inst0_1_bxt:
						return(arm_bxt(cj));
						break;
					case _arm_inst0_1_mrs:
						return(arm_mrs(cj));
						break;
					case _arm_inst0_1_msr:
						return(arm_msr(cj));
						break;
					default:
						CORE_TRACE("0x%08x", IR & _arm_inst0_1_mask);
						LOG_ACTION(exit(-1));
						break;
				}
			}break;
		case 0x01:
			if(_arm_inst1_mi2sr == (IR & _arm_inst1_mask))
				return(arm_msr(cj));
			else if(_arm_inst1_undefined != (IR & _arm_inst1_mask))
				return(arm_dpi_i(cj));
			break;
		case 0x02:
			return(arm_ldst_i(cj));
			break;
		case 0x04:
			return(arm_ldstm(cj));
			break;
		case 0x05:
			return(arm_b_bl(cj));
			break;
		case 0x07:
			if(_arm_inst7_mcr_mrc == (IR & _arm_inst7_mask))
				return(arm_mcr_mrc(cj));
			break;
	}
	
	CORE_TRACE_START("IR[27, 25] = 0x%02x", ir_27_25);

	switch(ir_27_25) {
		case 0x00:
		case 0x01:
			_CORE_TRACE_("DPI_OP = 0x%02x (%s), IR[7] = %0u, IR[4] = %0u",
				ARM_DPI_OP, dpi_op_string[ARM_DPI_OP], BEXT(IR, 7), BEXT(IR, 4));
			break;
		case 0x07:
			_CORE_TRACE_("IR[27:24] = 0x%02x, IR[4] = %u", mlBFEXT(IR, 27, 24), BEXT(IR, 4));
			break;
		default:
			break;
	}

	CORE_TRACE_END();

	return(0);
}
