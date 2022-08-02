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

int csx_trace_core(csx_core_p core)
{
	const csx_p csx = core->csx;
//	csx_core_p core = csx->core;
	
	const uint32_t pc = csx_reg_get(core, rTEST(rPC));
	
	csx_trace_p trace = csx->trace.head;
	
	if(!trace)
		return(1);
	
	if(_in_bounds(pc, sizeof(uint32_t), trace->start, trace->stop))
		return(1);
	
	return(0);
}

void csx_trace_psr(csx_core_p core, const char* pfn, uint32_t psr)
{
	char	tout[256], *dst = tout, *end = &tout[255];


	dst += snprintf(dst, end - dst, "%c", BEXT(psr, 31) ? 'N': 'n');
	dst += snprintf(dst, end - dst, "%c", BEXT(psr, 30) ? 'Z': 'z');
	dst += snprintf(dst, end - dst, "%c", BEXT(psr, 29) ? 'C': 'c');
	dst += snprintf(dst, end - dst, "%c:", BEXT(psr, 28) ? 'V': 'v');
	dst += snprintf(dst, end - dst, ":%c:", BEXT(psr, 27) ? 'Q': 'q');
	dst += snprintf(dst, end - dst, ":0x%01x:", mlBFEXT(psr, 26, 25));
	dst += snprintf(dst, end - dst, ":%c:", BEXT(psr, 24) ? 'J': 'j');
	dst += snprintf(dst, end - dst, ":0x%01x:", mlBFEXT(psr, 23, 20));
	dst += snprintf(dst, end - dst, ":GE[19:16] = %1x:", mlBFEXT(psr, 19, 16) & 0x0f);
	dst += snprintf(dst, end - dst, ":0x%02x:", mlBFEXT(psr, 15, 10));
	dst += snprintf(dst, end - dst, ":%c", BEXT(psr, 9) ? 'E': 'e');
	dst += snprintf(dst, end - dst, "%c", BEXT(psr, 8) ? 'A': 'a');
	dst += snprintf(dst, end - dst, "%c", BEXT(psr, 7) ? 'I': 'i');
	dst += snprintf(dst, end - dst, "%c", BEXT(psr, 6) ? 'F': 'f');
	dst += snprintf(dst, end - dst, "%c:", BEXT(psr, 5) ? 'T': 't');
	const uint8_t mode = mlBFEXT(psr, 4, 0);
	dst += snprintf(dst, end - dst, ":M[4:0] = 0x%01x", mode);
	
	const char* mode_string = csx_trace_psr_mode_string[mode & 0x0f];
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
		dst += snprintf(dst, end - dst, "%s", _arm_reg_name(dpi->rd));

	if((dpi->rn & 0x0f) == dpi->rn)
		dst += snprintf(dst, end - dst, "%s%s", dpi->wb ? ", " : "", _arm_reg_name(dpi->rn));

	if(dpi->bit.i)
	{
		dst += snprintf(dst, end - dst, ", %u", dpi->rm_v);

		if(dpi->rs_v)
			dst += snprintf(dst, end - dst, ", %u", dpi->rs_v);
	}
	else
	{
		dst += snprintf(dst, end - dst, ", %s", _arm_reg_name(dpi->rm));

		const char* sos = csx_core_arm_decode_shifter_op_string(dpi->shift_op);

		if(dpi->bit.x4)
			dst += snprintf(dst, end - dst, ", %s(%s)", sos, _arm_reg_name(dpi->rs));
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

	dst += snprintf(dst, end - dst, "(%s, %s", _arm_reg_name(ls->rd), _arm_reg_name(ls->rn));

	if((ls->rm & 0x0f) == ls->rm)
		dst += snprintf(dst, end - dst, "[%s]", _arm_reg_name(ls->rm));
	else if(ls->rm_v)
		dst += snprintf(dst, end - dst, "[0x%04x]%s", ls->rm_v, ls->bit.w ? "!" : "");
	else
		dst += snprintf(dst, end - dst, "[0]");
	
	dst += snprintf(dst, end - dst, ") /* 0x%08x: 0x%08x */",
		ls->ea, ls->rd_v);

	CORE_TRACE("%s", tout);
}
