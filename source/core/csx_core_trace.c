#include "csx.h"
#include "csx_core.h"

static const char* csx_trace_psr_mode_string[] = {
	[0x00] = "User",
	[0x01] = "FIQ",
	[0x02] = "IRQ",
	[0x03] = "Supervisor",
	[0x07] = "Abort",
	[0x08 + 0x03] = "Undefined",
	[0x08 + 0x07] = "System",
};

void csx_trace_psr(csx_core_p core, const char* pfn, uint32_t psr)
{
	char	tout[256], *dst = tout, *end = &tout[255];


	dst += snprintf(dst, end - dst, "%c", BIT_OF(psr, 31) ? 'N': 'n');
	dst += snprintf(dst, end - dst, "%c", BIT_OF(psr, 30) ? 'Z': 'z');
	dst += snprintf(dst, end - dst, "%c", BIT_OF(psr, 29) ? 'C': 'c');
	dst += snprintf(dst, end - dst, "%c:", BIT_OF(psr, 28) ? 'V': 'v');
	dst += snprintf(dst, end - dst, ":%c:", BIT_OF(psr, 27) ? 'Q': 'q');
	dst += snprintf(dst, end - dst, ":0x%01x:", (psr >> 25) & 0x03);
	dst += snprintf(dst, end - dst, ":%c:", psr & _BV(24) ? 'J': 'j');
	dst += snprintf(dst, end - dst, ":0x%01x:", (psr >> 20) & 0x0f);
	dst += snprintf(dst, end - dst, ":GE[19:16] = %1x:", (psr >> 16) & 0x0f);
	dst += snprintf(dst, end - dst, ":0x%02x:", (psr >> 10) & 0x3f);
	dst += snprintf(dst, end - dst, ":%c", BIT_OF(psr, 9) ? 'E': 'e');
	dst += snprintf(dst, end - dst, "%c", BIT_OF(psr, 8) ? 'A': 'a');
	dst += snprintf(dst, end - dst, "%c", BIT_OF(psr, 7) ? 'I': 'i');
	dst += snprintf(dst, end - dst, "%c", BIT_OF(psr, 6) ? 'F': 'f');
	dst += snprintf(dst, end - dst, "%c:", BIT_OF(psr, 5) ? 'T': 't');
	uint8_t mode = psr & 0x1f;
	dst += snprintf(dst, end - dst, ":M[4:0] = 0x%01x", mode);
	
	const char* mode_string = csx_trace_psr_mode_string[mode & 0xf];
	if(!mode_string)
		mode_string = "";

	TRACE("%s (%s) : %s", tout, mode_string, pfn ? pfn : "");
}

void csx_trace_psr_change(csx_core_p core, const char* pfn, uint32_t saved_psr, uint32_t new_psr)
{
	csx_trace_psr(core, pfn, saved_psr);
	csx_trace_psr(core, pfn, new_psr);
}

/* **** */

void csx_trace_inst_dpi(csx_core_p core, uint32_t opcode, csx_dpi_p dpi, uint8_t cce)
{
	char	tout[256], *dst = tout, *end = &tout[255];

	dst += snprintf(dst, end - dst, "%s%s(",
			dpi->mnemonic, dpi->bit.s ? "s" : "");

	if(dpi->wb)
		dst += snprintf(dst, end - dst, "rd(%u)", dpi->rd);

	if((dpi->rn & 0x0f) == dpi->rn)
		dst += snprintf(dst, end - dst, "%srn(%u)", dpi->wb ? ", " : "", dpi->rn);

	if(dpi->bit.i)
	{
		dst += snprintf(dst, end - dst, ", %u", dpi->rm_v);

		if(dpi->rs_v)
			dst += snprintf(dst, end - dst, ", %u", dpi->rs_v);
	}
	else
	{
		dst += snprintf(dst, end - dst, ", rm(%u)", dpi->rm);

		const char* sos = csx_core_arm_decode_shifter_op_string(dpi->shift_op);

		if(dpi->bit.x4)
			dst += snprintf(dst, end - dst, ", %s(rs(%u))", sos, dpi->rs);
		else if(dpi->rs_v)
			dst += snprintf(dst, end - dst, ", %s(%u)", sos, dpi->rs_v);
		else if(CSX_SHIFTER_OP_ROR == dpi->shift_op)
			dst += snprintf(dst, end - dst, ", RRX");
	}
	
	CORE_TRACE("%s) %s", tout, dpi->op_string);
}

void csx_trace_inst_ldst(csx_core_p core, uint32_t opcode, csx_ldst_p ls, uint8_t cce)
{
	char	tout[256], *dst = tout, *end = &tout[255];

	/* ldr|str{cond}{b}{t} <rd>, <addressing_mode> */
	/* ldr|str{cond}{h|sh|sb|d} <rd>, <addressing_mode> */
	
	dst += snprintf(dst, end - dst, "%sr", ls->bit.l ? "ld" : "st");
	
	if(0x01 == ls->bit.i2x_76)
	{
		int bit_t = !ls->bit.p && ls->bit.w;

		dst += snprintf(dst, end - dst, "%s%s",
			ls->bit.b ? "b" : "", bit_t ? "t" : "");
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

	dst += snprintf(dst, end - dst, "(rd(%u), rn(%u)", ls->rd, ls->rn);

	if((ls->rm & 0x0f) == ls->rm)
		dst += snprintf(dst, end - dst, "[rm(%u)]", ls->rm);
	else if(ls->rm_v)
		dst += snprintf(dst, end - dst, "[0x%04x]", ls->rm_v);
	else
		dst += snprintf(dst, end - dst, "[0]");
	
	dst += snprintf(dst, end - dst, ") /* 0x%08x: 0x%08x */",
		ls->ea, ls->rd_v);

	CORE_TRACE("%s", tout);
}
