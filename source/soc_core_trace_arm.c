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
			dpi->mnemonic, DPI_BIT(s20) ? "s" : "");

	if(dpi->wb)
		_CORE_TRACE_("%s", _arm_reg_name(rR(D)));

	if((rR(N) & 0x0f) == rR(N))
		_CORE_TRACE_("%s%s", dpi->wb ? ", " : "", _arm_reg_name(rR(N)));

	if(DPI_BIT(i25))
	{
		if(vR(S)) {
			_CORE_TRACE_(", ROR(%u, %u)", vR(M), vR(S));
		} else
			_CORE_TRACE_(", %u", vR(M));
	}
	else
	{
		const char* sos = soc_core_arm_decode_shifter_op_string(DPI_SHIFT_OP);
		
		if(DPI_BIT(x4))
			_CORE_TRACE_(", %s(%s, %s)", sos, _arm_reg_name(rR(M)), _arm_reg_name(rR(S)));
		else {
			switch(DPI_SHIFT_OP) {
				case SOC_CORE_SHIFTER_OP_ROR:
					if(!vR(S))
						_CORE_TRACE_(", RRX(%s)", sos, _arm_reg_name(rR(M)));
					break;
				default:
					if(!mlBFEXT(IR, 11, 4))
						_CORE_TRACE_(", %s", _arm_reg_name(rR(M)));
					else
						_CORE_TRACE_(", %s(%s, %u)", sos, _arm_reg_name(rR(M)), vR(S));
					break;
			}
		}
	}

	_CORE_TRACE_(")");

	if(dpi->op_string[0])
		_CORE_TRACE_(" %s", dpi->op_string);

	CORE_TRACE_END();
}

void soc_core_trace_inst_ldst(soc_core_p core, soc_core_ldst_p ls)
{
	CORE_TRACE_START();

	/* ldr|str{cond}{b}{t} <rd>, <addressing_mode> */
	/* ldr|str{cond}{h|sh|sb|d} <rd>, <addressing_mode> */

	_CORE_TRACE_("%sr", LDST_BIT(l20) ? "ld" : "st");

	if(LDSTX & 1)
	{
		const int bit_t = !LDST_BIT(p24) && LDST_BIT(w21);

		_CORE_TRACE_("%s%s", LDST_BIT(b22) ? "b" : "", bit_t ? "t" : "");
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

		_CORE_TRACE_("%s%s", LDST_FLAG_S ? "s" : "", rws);
	}

	_CORE_TRACE_("(%s, %s", _arm_reg_name(rR(D)), _arm_reg_name(rR(N)));

	if((rR(M) & 0x0f) == rR(M))
		_CORE_TRACE_("[%s]", _arm_reg_name(rR(M)));
	else if(vR(M))
		_CORE_TRACE_("[0x%04x]%s", vR(M), LDST_BIT(w21) ? "!" : "");
	else
		_CORE_TRACE_("[0]");

	_CORE_TRACE_(") /* 0x%08x: 0x%08x */", ls->ea, vR(D));

	CORE_TRACE_END();
}
