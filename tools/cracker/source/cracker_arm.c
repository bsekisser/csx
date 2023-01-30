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

#include "cracker_alubox.h"

static uint32_t _fetch(cracker_p cj)
{
	PC += sizeof(uint32_t);

	return(_read(cj, IP, sizeof(uint32_t)));
}

static void _shifter_operand(cracker_p cj)
{
	switch(ARM_DPI_SOP) {
		case SOP_ASR:
			vR(SOP) = _asr(vR(M), vR(S));
			break;
		case SOP_LSL:
			vR(SOP) = _lsl(vR(M), vR(S));
			break;
		case SOP_LSR:
			vR(SOP) = _lsr(vR(M), vR(S));
			break;
		case SOP_ROR:
			vR(SOP) = _ror(vR(M), vR(S));
			break;
	}
}

/* **** */

static int arm_b_bl(cracker_p cj)
{
	const int blx = (CC_NV == ARM_IR_CC);
	const int hl = BEXT(IR, 24);
	const int32_t offset = mlBFMOVs(IR, 23, 0, 2);
	
	const int link = blx || (!blx && hl);
	const uint32_t new_pc = ARM_PC + offset;

	CORE_TRACE("B%s%s(0x%08x)", link ? "L" : "", blx ? "X" : "", new_pc);
	
	cracker_text(cj, new_pc);

	if(link || (ARM_IR_CC != CC_AL)) {
		symbol_p slr = cracker_text(cj, PC);

		return(slr->pass);
	}

	return(0);
}

static int arm_bxt(cracker_p cj)
{
	assert(0xf == mlBFEXT(IR, 19, 16));
	assert(0xf == mlBFEXT(IR, 15, 12));
	assert(0xf == mlBFEXT(IR, 11, 8));

	setup_rR_vR_src(M, ARM_IR_RM);

	CORE_TRACE_START();

	_CORE_TRACE_("BX(%s)", rR_NAME(M));

	if(rPC == rR_SRC(M)) {
		_CORE_TRACE_("; /* 0x%08x */", vR(M));

		cracker_text(cj, vR(M));
	}

	CORE_TRACE_END();
		
	return(0);
}

static int arm_cdp_mcr_mrc(cracker_p cj)
{
	int is_cdp = (0 == BEXT(IR, 4));
	int is_mrc = BEXT(IR, 20);

	if(is_cdp || is_mrc) {
		setup_rR_dst(D, ARM_IR_RD);
	} else
		setup_rR_src(D, ARM_IR_RD);

	CORE_TRACE_START();
	
	_CORE_TRACE_("%s(CP%u, %u, %s, CRn(%u), CRm(%u)",
		(is_cdp ? "CDP" : (is_mrc ? "MCR" : "MRC")),
		mlBFEXT(IR, 11, 8), mlBFEXT(IR, 23, 21), rR_NAME(D),
		mlBFEXT(IR, 19, 16), mlBFEXT(IR, 3, 0));
	
	uint op2 = mlBFEXT(IR, 7, 5);

	if(op2) {
		_CORE_TRACE_(", %u)", op2);
	}
	
	CORE_TRACE_END();
	
	return(rPC != ARM_IR_RD);
}

static void arm_dpi(cracker_p cj)
{
	int wb = 0;

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
			wb = 1;
			setup_rR_vR_src(N, ARM_IR_RN);
			setup_rR_vR_dst_src(D, ARM_IR_RD, rR(N));

			_CORE_TRACE_("%s%s(%s, %s, ",
				dpi_op_string[ARM_DPI_OP], ARM_DPI_S ? "S" : "",
				rR_NAME(D), rR_NAME(N));
			break;
		case ARM_CMP:
		case ARM_CMN:
		case ARM_TEQ:
		case ARM_TST:
			setup_rR_src(N, ARM_IR_RN);

			assert(0 == mlBFEXT(IR, 15, 12));
			_CORE_TRACE_("%s(%s, ", dpi_op_string[ARM_DPI_OP], rR_NAME(N));
			break;
		case ARM_MOV:
		case ARM_MVN:
			setup_rR_dst(D, ARM_IR_RD);

			assert(0 == mlBFEXT(IR, 19, 16));
			_CORE_TRACE_("%s%s(%s, ",
				dpi_op_string[ARM_DPI_OP], ARM_DPI_S ? "S" : "",
				rR_NAME(D));
			break;
		default:
			CORE_TRACE_END("0x%02x, %s", ARM_DPI_OP, dpi_op_string[ARM_DPI_OP]);
			LOG_ACTION(exit(-1));
			break;
	}

	if((CC_AL == ARM_IR_CC) && (rPC == rR_SRC(D)))
	{
		if(wb) {
			vR(D) = alubox(ARM_DPI_OP, vR(D), vR(SOP));

			vGPR_rR(D) = vR(D);
			if(rPC == rR(D))
				cracker_text(cj, vR(D));
		}
	}
}

static int arm_dpi_i(cracker_p cj)
{
	const uint shift = mlBFMOV(IR, 11, 8, 1);
	const uint imm8 = mlBFEXT(IR, 7, 0);

	setup_rR_vR(SOP, ~0, _ror(imm8, shift));

	arm_dpi(cj);

	if(shift) {
		_CORE_TRACE_("ROR(%u, %u)); /* 0x%08x */", imm8, shift, vR(SOP));
	} else {
		_CORE_TRACE_("%u)", vR(SOP));
		if(rPC == rR(D)) {
			_CORE_TRACE_("; /* 0x%08x */", vR(D));
		}
	}
	
	CORE_TRACE_END();

	return(rPC != ARM_IR_RD);
}

static int arm_dpi_rs(cracker_p cj)
{
	setup_rR_src(M, ARM_IR_RM);
	setup_rR_src(S, ARM_IR_RS);

	_shifter_operand(cj);

	arm_dpi(cj);

	CORE_TRACE_END("%s(%s, %s))",
		shift_op_string[ARM_DPI_SOP],
		rR_NAME(M), rR_NAME(S));
	
	return(rPC != ARM_IR_RD);
}

static int arm_dpi_s(cracker_p cj) {
	setup_rR_src(M, ARM_IR_RM);
	setup_rR_vR(S, ~0, mlBFEXT(IR, 11, 7));
	
	switch(ARM_DPI_SOP) {
		case SOP_ASR:
		case SOP_LSR:
			if(0 == vR(S))
				vR(S) = 32;
			break;
	}

	_shifter_operand(cj);

	arm_dpi(cj);
	
	if(vR(S)) {
		CORE_TRACE_END("%s(%s, 0x%02x))",
			shift_op_string[ARM_DPI_SOP],
			rR_NAME(M), vR(S));
	} else {
		if(SOP_ROR == ARM_DPI_SOP) {
			CORE_TRACE_END("RRX(%s))", rR_NAME(M));
		} else {
			CORE_TRACE_END("%s)", rR_NAME(M));
		}
	}
	
	return(rPC != ARM_IR_RD);
}

static int arm_ldc_stc(cracker_p cj)
{
//	const uint32_t op0 = mlBFTST(IR, 27, 24) | BTST(IR, 4);
	setup_rR_src(N, mlBFEXT(IR, 19, 16));
	setup_rR_dst(D, mlBFEXT(IR, 15, 12));
	const uint8_t cp = mlBFEXT(IR, 11, 8);
	
	CORE_TRACE_START();
	
	_CORE_TRACE_("%sC%s(CP%u, CRd(%u)",
		BEXT(IR, 20) ? "LD" : "ST", BEXT(IR, 22) ? "L" : "",
		cp, rR(D));

	const uint8_t offset = mlBFMOV(IR, 7, 0, 2);

	_CORE_TRACE_(", CRn(%u)%s, %s0x%03x",
		rR(N), BEXT(IR, 21) ? ".WB " : "", BEXT(IR, 23) ? "" : "-", offset);

	CORE_TRACE_END(")");

	return(rPC != ARM_IR_RD);
}

static int arm_ldst(cracker_p cj)
{
	setup_rR_vR_src(N, ARM_IR_RN);

	if(ARM_LDST_L) {
		setup_rR_dst_src(D, ARM_IR_RD, rR(N));
	} else {
		setup_rR_src(D, ARM_IR_RD);
	}

	CORE_TRACE_START();
	
	/* ldr|str{cond}{b}{t} <rd>, <addressing_mode> */
	/* ldr|str{cond}{h|sh|sb|d} <rd>, <addressing_mode> */

	switch(mlBFEXT(IR, 27, 25) & ~1) {
		case 0x00: { /* miscellaneous load/store */
			const int ldst_l = ARM_LDST_L || (!ARM_LDST_L && !ARM_LDST_H);
			
			_CORE_TRACE_("%sR", ldst_l ? "LD" : "ST");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_S ? "S" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_H ? "H" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_B ? "B" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_D ? "D" : "");
		}break;
		case 0x02: { /* default load store */
			const int ldst_t = !ARM_LDST_P && ARM_LDST_W;

			_CORE_TRACE_("%sR", ARM_LDST_L ? "LD" : "ST");
			_CORE_TRACE_("%s%s", ARM_LDST_B ? "B" : "", ldst_t ? "T" : "");
		}break;
		default:
			CORE_TRACE("/* XXX */");
			return(-1);
	}

	_CORE_TRACE_("(%s, ", rR_NAME(D));

	const int wb = !ARM_LDST_P || (ARM_LDST_P && ARM_LDST_W);
	_CORE_TRACE_("%s%s", rR_NAME(N), wb ? " | rWB" : "");

	return(0);
}

static int arm_ldst_i(cracker_p cj)
{
	if(arm_ldst(cj))
		return(0);
	
	int32_t offset = mlBFEXT(IR, 11, 0);
	
	_CORE_TRACE_(", %s0x%04x", ARM_LDST_U ? "+" : "-", offset);
	
	_CORE_TRACE_(")");

	if(!ARM_LDST_U)
		offset = ~offset;

	const uint32_t pat = vR(N) + offset;
	const size_t size = ARM_LDST_B ? sizeof(uint8_t) : sizeof(uint32_t);

	int is_rPC = (rPC == rR(N));
	int is_rPC_SRC = (rPC == rR_SRC(N));

	if(is_rPC || is_rPC_SRC) {
		cracker_data(cj, pat, size);

		_CORE_TRACE_("; /* [0x%08x]", pat);

		if(is_rPC) {
			const uint32_t data = _read(cj, pat, size);

			if(ARM_LDST_B) {
				_CORE_TRACE_(":0x%02x", data);
			} else {
				vGPR_rR(D) = data;
				_CORE_TRACE_(":0x%08x", data);
			}
		}

		_CORE_TRACE_(" */");
	}

	CORE_TRACE_END();
	
	return(rPC != ARM_IR_RD);
}

static int arm_ldst_r(cracker_p cj)
{
	if(arm_ldst(cj))
		return(0);

	setup_rR_src(M, ARM_IR_RM);
	setup_rR_vR(S, ~0, mlBFEXT(IR, 11, 7));

	if(0 == mlBFEXT(IR, 11, 4)) {
		_CORE_TRACE_(", %s%s", ARM_LDST_U ? "+" : "-", rR_NAME(M));
	} else {
		uint shift = mlBFEXT(IR, 6, 5);

		switch(rR(S)) {
			case SOP_ASR:
			case SOP_LSR:
				if(0 == rR(S))
					rR(S) = 32;
				break;
		}
		
		_CORE_TRACE_("%s(%s, %u)", shift_op_string[shift],
			rR_NAME(M), vR(S));
	}

	CORE_TRACE_END(")");

	return(rPC != ARM_IR_RD);
}

static int arm_ldst_sh(cracker_p cj)
{
	if(arm_ldst(cj))
		return(0);
	
	if(ARM_LDST_I22) {
		int16_t offset = mlBFMOV(IR, 11, 8, 4) | mlBFEXT(IR, 3, 0);

		_CORE_TRACE_(", %s0x%04x", ARM_LDST_U ? "+" : "-", offset);

		if(!ARM_LDST_U)
			offset = ~offset;

		if(rPC == rR_SRC(N)) {
			const uint32_t pat = vR(N) + offset;
			const size_t size = 1 << ARM_LDST_FLAG_H;

			cracker_data(cj, pat, size);

			_CORE_TRACE_("); /* [0x%08x] */", pat);
		}
	} else {
//		assert(0 == mlBFEXT(IR, 11, 8));
		if(0 != mlBFEXT(IR, 11, 8)) {
			CORE_TRACE_END("XXX");
			return(0);
		}

		setup_rR_src(M, ARM_IR_RM);
		
		_CORE_TRACE_(", %s%s", ARM_LDST_U ? "" : "-", rR_NAME(M));
	}
	
//	CORE_TRACE_END(")");
	CORE_TRACE_END();
	
	return(rPC != ARM_IR_RD);
}

static int arm_ldstm(cracker_p cj)
{
	setup_rR_src(N, ARM_IR_RN);

	CORE_TRACE_START("%sM", ARM_LDST_L ? "LD" : "ST");
	_CORE_TRACE_("%c%c", ARM_LDST_U ? 'I' : 'D', ARM_LDST_P ? 'B' : 'A');
	_CORE_TRACE_("(%s%s, ", rR_NAME(N), ARM_LDST_W ? ".WB " : "");
	
	char reglist[17], *dst = reglist;
	
	for(int i = 0; i <= 15; i++) {
		if(BEXT(IR, i))
			*dst++ = (i <= 9  ? '0' : 'a' - 10) + i;
		else
			*dst++ = '.';
	}

	*dst = 0;

	CORE_TRACE_END("{%s}%s)", reglist, ARM_LDSTM_S ? ".S" : "");
	
	const int ldpc = ARM_LDST_L && BEXT(IR, PC);
	
	return(!(ldpc && (CC_AL == ARM_IR_CC)));
}

static int arm_mrs(cracker_p cj)
{
	assert(0xf == mlBFEXT(IR, 19, 16));
	assert(0 == mlBFEXT(IR, 11, 0));

	setup_rR_dst(D, ARM_IR_RD);

	int bit_r = BEXT(IR, 22);

	CORE_TRACE("MRS(%s, %cPSR)",
		rR_NAME(D), bit_r ? 'S' : 'C');

	return(rPC != ARM_IR_RD);
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
		_CORE_TRACE_("MSR(%cPSR_%s, ",
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
		setup_rR_src(M, ARM_IR_RM);

		if(0 != mlBFEXT(IR, 11, 8)) {
			CORE_TRACE_END("/* XXX */");
		}

		_CORE_TRACE_("MSR(%cPSR_%s, %s",
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

	uint ir_27_25 = mlBFEXT(IR, 27, 25);

	if(CC_NV != ARM_IR_CC) {
		switch(ir_27_25) {
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
							goto fail_decode;
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
			case 0x03:
				return(arm_ldst_r(cj));
				break;
			case 0x04:
				return(arm_ldstm(cj));
				break;
			case 0x05:
				return(arm_b_bl(cj));
				break;
			case 0x06:
				return(arm_ldc_stc(cj));
				break;
			case 0x07:
				if(_arm_inst7_mcr_mrc == (IR & _arm_inst7_mask))
					return(arm_cdp_mcr_mrc(cj));
				break;
		}
	} else { /* CC_NV */
		switch(ir_27_25) {
			case 0x05:
				return(arm_b_bl(cj));
				break;
		}
	}

fail_decode:
	CORE_TRACE_START("IR[27, 25] = 0x%02x", ir_27_25);

	switch(ir_27_25) {
		case 0x00:
		case 0x01:
			_CORE_TRACE_(", DPI_OP = 0x%02x (%s), IR[7] = %0u, IR[4] = %0u",
				ARM_DPI_OP, dpi_op_string[ARM_DPI_OP], BEXT(IR, 7), BEXT(IR, 4));
			break;
		case 0x07:
			_CORE_TRACE_(", IR[27:24] = 0x%02x, IR[4] = %u", mlBFEXT(IR, 27, 24), BEXT(IR, 4));
			break;
		default:
			break;
	}

	CORE_TRACE_END("/* XXX */");

	return(0);
}
