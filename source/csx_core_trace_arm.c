#include "csx.h"
#include "csx_core.h"
#include "csx_core_arm_decode.h"
#include "csx_core_reg_trace.h"

void csx_trace_inst_dpi(csx_core_p core, csx_dpi_p dpi, uint8_t cce)
{
	char	tout[256], *dst = tout, *end = &tout[255];

	dst += snprintf(dst, end - dst, "%s%s(",
			dpi->mnemonic, dpi->bit.s ? "s" : "");

	if(dpi->wb)
		dst += snprintf(dst, end - dst, "%s", _arm_reg_name(rR(D)));

	if((rR(N) & 0x0f) == rR(N))
		dst += snprintf(dst, end - dst, "%s%s", dpi->wb ? ", " : "", _arm_reg_name(rR(N)));

	if(dpi->bit.i)
	{
		dst += snprintf(dst, end - dst, ", %u", vR(M));

		if(vR(S))
			dst += snprintf(dst, end - dst, ", %u", vR(S));
	}
	else
	{
		dst += snprintf(dst, end - dst, ", %s", _arm_reg_name(rR(M)));

		const char* sos = csx_core_arm_decode_shifter_op_string(dpi->shift_op);

		if(dpi->bit.x4)
			dst += snprintf(dst, end - dst, ", %s(%s)", sos, _arm_reg_name(rR(S)));
		else if(vR(S))
			dst += snprintf(dst, end - dst, ", %s(%u)", sos, vR(S));
		else if(CSX_SHIFTER_OP_ROR == dpi->shift_op)
			dst += snprintf(dst, end - dst, ", RRX");
	}
	
	CORE_TRACE("%s) %s", tout, dpi->op_string);
}

void csx_trace_inst_ldst(csx_core_p core, csx_ldst_p ls, uint8_t cce)
{
	char	tout[256], *dst = tout, *end = &tout[255];

	/* ldr|str{cond}{b}{t} <rd>, <addressing_mode> */
	/* ldr|str{cond}{h|sh|sb|d} <rd>, <addressing_mode> */
	
	dst += snprintf(dst, end - dst, "%sr", ls->bit.l ? "ld" : "st");
	
	if(ls->ldstx & 1)
	{
		const int bit_t = !ls->bit.p && ls->bit.w;

		dst += snprintf(dst, end - dst, "%s%s",
			ls->bit.b22 ? "b" : "", bit_t ? "t" : "");
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

		dst += snprintf(dst, end - dst, "%s%s", ls->flags.s ? "s" : "", rws);
	}

	dst += snprintf(dst, end - dst, "(%s, %s", _arm_reg_name(rR(D)), _arm_reg_name(rR(N)));

	if((rR(M) & 0x0f) == rR(M))
		dst += snprintf(dst, end - dst, "[%s]", _arm_reg_name(rR(M)));
	else if(vR(M))
		dst += snprintf(dst, end - dst, "[0x%04x]%s", vR(M), ls->bit.w ? "!" : "");
	else
		dst += snprintf(dst, end - dst, "[0]");
	
	dst += snprintf(dst, end - dst, ") /* 0x%08x: 0x%08x */",
		ls->ea, vR(D));

	CORE_TRACE("%s", tout);
}
