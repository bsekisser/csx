#include "soc_core_decode.h"

#include "soc_core_arm_decode.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"
#include "soc_core_shifter.h"

/* **** */

#include "bitfield.h"
#include "log.h"
#include "shift_roll.h"

/* **** */

void soc_core_arm_decode_coproc(soc_core_p core)
{
	rR(D) = MCRC_Rd;
	rR(M) = MCRC_CRm;
	rR(N) = MCRC_CRn;
}

static void _soc_core_arm_decode_dpi(soc_core_p core, soc_core_dpi_p dpi)
{
	_setup_rR_vR(M, ~0, mlBFEXT(IR, 7, 0));
	_setup_rR_vR(S, ~0, mlBFMOV(IR, 11, 8, 1));
}

static void _soc_core_arm_decode_dpis(soc_core_p core, soc_core_dpi_p dpi)
{
	_setup_rR_vR(S, ~0, mlBFEXT(IR, 11, 7));
	
	switch(DPI_SHIFT_OP) {
		case	SOC_CORE_SHIFTER_OP_ASR:
		case	SOC_CORE_SHIFTER_OP_LSR:
			if(!vR(S))
				vR(S) = 32;
			break;
	}
}

static void _soc_core_arm_decode_dprs(soc_core_p core, soc_core_dpi_p dpi)
{
	if(DPI_BIT(x7))
	{
		LOG("**** I = 0, x4 = 1, x7 = 1 ****");

		soc_core_disasm_arm(core, IP, IR);
		LOG_ACTION(exit(1));
	}

	soc_core_decode_get(core, rRS, 11, 8, 1);
	vR(S) &= _BM(7);
}

static void _soc_core_arm_shifter_operation_asr(soc_core_p core, soc_core_dpi_p dpi)
{
	int cout = 0;

	if(vR(S))
		dpi->out.v = _asr_c(vR(M), vR(S), &cout);
	else {
		dpi->out.v = vR(M);
		cout = BEXT(CPSR, SOC_CORE_PSR_BIT_C);
	}

	dpi->out.c = cout;
}

static void _soc_core_arm_shifter_operation_lsl(soc_core_p core, soc_core_dpi_p dpi)
{
	uint cout = 0;
	
	if(vR(S))
		dpi->out.v = _lsl_c(vR(M), vR(S), &cout);
	else {
		dpi->out.v = vR(M);
		cout = BEXT(CPSR, SOC_CORE_PSR_BIT_C);
	}

	dpi->out.c = cout;
}

static void _soc_core_arm_shifter_operation_lsr(soc_core_p core, soc_core_dpi_p dpi)
{
	uint cout = 0;

	if(vR(S))
		dpi->out.v = _lsr_c(vR(M), vR(S), &cout);
	else {
		dpi->out.v = vR(M);
		cout = BEXT(CPSR, SOC_CORE_PSR_BIT_C);
	}

	dpi->out.c = cout;
}

static void _soc_core_arm_shifter_operation_ror(soc_core_p core, soc_core_dpi_p dpi)
{
	if(!DPI_BIT(i25) && !DPI_BIT(x4) && (0 == vR(S)))
	{
		dpi->out.v = BMOV(CPSR, SOC_CORE_PSR_BIT_C, 31) | (vR(M) >> 1);
		dpi->out.c = vR(M) & 1;
	}
	else
	{
		dpi->out.v = _ror(vR(M), vR(S));
		if(vR(S))
		{
			if(DPI_BIT(i25))
			{
				dpi->out.c = BEXT(dpi->out.v, 31);
			}
			else if(mlBFEXT(vR(S), 4, 0))
				dpi->out.c = BEXT(vR(M), vR(S) - 1);
			else
			{
				dpi->out.v = vR(M);
				dpi->out.c = BEXT(vR(M), 31);
			}
		}
		else
			dpi->out.c = BEXT(CPSR, SOC_CORE_PSR_BIT_C);
	}
}

void soc_core_arm_decode_shifter_operand(soc_core_p core, soc_core_dpi_p dpi)
{
	dpi->wb = 1;

	if(DPI_BIT(i25))
		_soc_core_arm_decode_dpi(core, dpi);
	else
	{
		if(DPI_BIT(x4))
			_soc_core_arm_decode_dprs(core, dpi);
		else
			_soc_core_arm_decode_dpis(core, dpi);

		soc_core_arm_decode_rm(core, 1);
	}

	switch(DPI_SHIFT_OP)
	{
		case	SOC_CORE_SHIFTER_OP_ASR:
			_soc_core_arm_shifter_operation_asr(core, dpi);
			break;
		case	SOC_CORE_SHIFTER_OP_LSL:
			_soc_core_arm_shifter_operation_lsl(core, dpi);
			break;
		case	SOC_CORE_SHIFTER_OP_LSR:
			_soc_core_arm_shifter_operation_lsr(core, dpi);
			break;
		case	SOC_CORE_SHIFTER_OP_ROR:
			_soc_core_arm_shifter_operation_ror(core, dpi);
			break;
		default:
			LOG("**** i = %u, s = %u, x7 = %u, x4 = %u",
				!!DPI_BIT(i25), !!DPI_BIT(s20), !!DPI_BIT(x7), !!DPI_BIT(x4));

			LOG("**** imm = 0x%02x, shift = 0x%02x",
				vR(M), vR(S));

			LOG_ACTION(exit(1));
			break;
	}
}

static const char* shifter_op_string[] = {
	"LSL", "LSR", "ASR", "ROR"
};

const char* soc_core_arm_decode_shifter_op_string(const uint8_t shopc)
{
	return(shifter_op_string[shopc & 0x03]);
}
