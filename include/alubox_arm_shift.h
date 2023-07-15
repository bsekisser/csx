#pragma once

/* **** */

#include "alubox.h"
#include "soc_core.h"

/* **** */

__ALUBOX_STATIC__
void __alubox_arm_shift_c(soc_core_p core)
{
	unsigned carry_out = 0;

	switch(rR(SOP_C)) {
		case __alubox_shift_asr:
			carry_out = _asr_c(vR(M), vR(S));
			break;
		case __alubox_shift_lsl:
			carry_out = _lsl_c(vR(M), vR(S));
			break;
		case __alubox_shift_lsr:
			carry_out = _lsr_c(vR(M), vR(S));
			break;
		case __alubox_shift_ror:
			carry_out = _ror_c(vR(M), vR(S));
			break;
		case __alubox_shift_rrx:
			carry_out = _rrx_c(vR(M));
			break;
	}

//	vR(SOP_C) = carry_out;
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, !!carry_out);
}

__ALUBOX_STATIC__
void __alubox_arm_shift_sop(soc_core_p core)
{
	const unsigned carry_in = BEXT(CPSR, SOC_CORE_PSR_BIT_C);

	switch(rR(SOP_C)) {
		case __alubox_shift_asr:
			vR(SOP_V) = _asr(vR(M), vR(S));
			break;
		case __alubox_shift_lsl:
			vR(SOP_V) = _lsl(vR(M), vR(S));
			break;
		case __alubox_shift_lsr:
			vR(SOP_V) = _lsr(vR(M), vR(S));
			break;
		case __alubox_shift_ror:
			vR(SOP_V) = _ror(vR(M), vR(S));
			break;
		case __alubox_shift_rrx:
			vR(SOP_V) = _rrx_v(vR(M), carry_in);
			break;
		default:
			exit(-1);
	}

	const char* sts[5] = {
		[__alubox_shift_asr] = "asr",
		[__alubox_shift_lsl] = "lsl",
		[__alubox_shift_lsr] = "lsr",
		[__alubox_shift_ror] = "ror",
		[__alubox_shift_rrx] = "rrx",
	};

	if(0) LOG("rrm: 0x%08x, rrs: 0x%08x", rR(M), rR(S));

	if(0) LOG("shift_type: %01u, %s(rm: 0x%08x, rs: 0x%08x) --> sop: 0x%08x, C: %01u",
		rR(SOP_C), sts[rR(SOP_C)], vR(M), vR(S), vR(SOP_V), carry_in);
}
