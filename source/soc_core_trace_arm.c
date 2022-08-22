#include "soc_core_trace_arm.h"

#include "soc_core_psr.h"
#include "soc_core_reg_trace.h"
#include "soc_core_shifter.h"
#include "soc_core_trace.h"

#include "csx_state.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

void soc_core_trace_inst_dpi(soc_core_p core, soc_core_dpi_p dpi)
{
	CORE_TRACE_START();

	_CORE_TRACE_("%s%s(",
			dpi->mnemonic, dpi->bit.s ? "s" : "");

	if(dpi->wb)
		_CORE_TRACE_("%s", _arm_reg_name(rR(D)));

	if((rR(N) & 0x0f) == rR(N))
		_CORE_TRACE_("%s%s", dpi->wb ? ", " : "", _arm_reg_name(rR(N)));

	if(dpi->bit.i)
	{
		_CORE_TRACE_(", %u", vR(M));

		if(vR(S))
			_CORE_TRACE_(", %u", vR(S));
	}
	else
	{
		_CORE_TRACE_(", %s", _arm_reg_name(rR(M)));

		const char* sos = soc_core_arm_decode_shifter_op_string(dpi->shift_op);

		if(dpi->bit.x4)
			_CORE_TRACE_(", %s(%s)", sos, _arm_reg_name(rR(S)));
		else if(vR(S))
			_CORE_TRACE_(", %s(%u)", sos, vR(S));
		else if(SOC_CORE_SHIFTER_OP_ROR == dpi->shift_op)
			_CORE_TRACE_(", RRX");
	}

	_CORE_TRACE_(") %s", dpi->op_string);

	CORE_TRACE_END();
}

void soc_core_trace_inst_ldst(soc_core_p core, soc_core_ldst_p ls)
{
	CORE_TRACE_START();

	/* ldr|str{cond}{b}{t} <rd>, <addressing_mode> */
	/* ldr|str{cond}{h|sh|sb|d} <rd>, <addressing_mode> */

	_CORE_TRACE_("%sr", ls->bit.l ? "ld" : "st");

	if(ls->ldstx & 1)
	{
		const int bit_t = !ls->bit.p && ls->bit.w;

		_CORE_TRACE_("%s%s", ls->bit.b22 ? "b" : "", bit_t ? "t" : "");
	}
	else
	{
		const char* rws = "";
		switch(ls->rw_size)
		{
			case sizeof(uint8_t):
				rws = "b";
				break;
			case sizeof(uint16_t):
				rws = "h";
				break;
			case sizeof(uint32_t):
				break;
			case sizeof(uint64_t):
				rws = "d";
				break;
			default:
				LOG_ACTION(core->csx->state = CSX_STATE_HALT);
				break;
		}

		_CORE_TRACE_("%s%s", ls->flags.s ? "s" : "", rws);
	}

	_CORE_TRACE_("(%s, %s", _arm_reg_name(rR(D)), _arm_reg_name(rR(N)));

	if((rR(M) & 0x0f) == rR(M))
		_CORE_TRACE_("[%s]", _arm_reg_name(rR(M)));
	else if(vR(M))
		_CORE_TRACE_("[0x%04x]%s", vR(M), ls->bit.w ? "!" : "");
	else
		_CORE_TRACE_("[0]");

	_CORE_TRACE_(") /* 0x%08x: 0x%08x */", ls->ea, vR(D));

	CORE_TRACE_END();
}
