#include "soc_core_trace.h"

#include "soc_core_psr.h"
#include "soc_core_strings.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/log.h"

/* **** */

static const char* soc_core_trace_psr_mode_string[] = {
	[0x00] = "User",
	[0x01] = "FIQ",
	[0x02] = "IRQ",
	[0x03] = "Supervisor",
	[0x07] = "Abort",
	[0x08 + 0x03] = "Undefined",
	[0x08 + 0x07] = "System",
};

/* **** */

void soc_core_trace(soc_core_p core, const char* format, ...)
{
	if(!core->trace)
		return;

	if(0) {
		printf("%c(0x%08x(0x%08x), %s(%c), ",
			(CPSR & SOC_CORE_PSR_T) ? 'T' : 'A',
			IP, IR,
			CCx.s, CCx.e ? '>' : 'X');
	} else
		soc_core_trace_start(core);

	va_list ap;
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);

	if(0)
		printf(")\n");
	else
		soc_core_trace_end(core);
}

void soc_core_trace_dump_regs(soc_core_p core)
{
	LOG_END();
	
	LOG_START("\n");
	unsigned i = 0;
	do {
		_LOG_("%s == 0x%08x", reg_name[1][i], GPR(i));
		i++;
		if(i < 16) {
			_LOG_("%s", (3 & i) ? ", " : "\n");
		}
	}while(i < 16);
	LOG_END();
}

void soc_core_trace_end(soc_core_p core)
{
	if(!core->trace)
		return;

	printf(")\n");
}

void soc_core_trace_out(soc_core_p core, const char* format, ...)
{
	if(!core->trace)
		return;

	va_list ap;
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

void soc_core_trace_psr(soc_core_p core, const char* pfn, uint32_t psr)
{
	LOG_START("%c", BEXT(psr, 31) ? 'N': 'n');
	_LOG_("%c", BEXT(psr, 30) ? 'Z': 'z');
	_LOG_("%c", BEXT(psr, 29) ? 'C': 'c');
	_LOG_("%c:", BEXT(psr, 28) ? 'V': 'v');
	_LOG_(":%c:", BEXT(psr, 27) ? 'Q': 'q');
	_LOG_(":0x%01x:", mlBFEXT(psr, 26, 25));
	_LOG_(":%c:", BEXT(psr, 24) ? 'J': 'j');
	_LOG_(":0x%01x:", mlBFEXT(psr, 23, 20));
	_LOG_(":GE[19:16] = %1x:", mlBFEXT(psr, 19, 16) & 0x0f);
	_LOG_(":0x%02x:", mlBFEXT(psr, 15, 10));
	_LOG_(":%c", BEXT(psr, 9) ? 'E': 'e');
	_LOG_("%c", BEXT(psr, 8) ? 'A': 'a');
	_LOG_("%c", BEXT(psr, 7) ? 'I': 'i');
	_LOG_("%c", BEXT(psr, 6) ? 'F': 'f');
	_LOG_("%c:", BEXT(psr, 5) ? 'T': 't');
	const uint8_t mode = mlBFEXT(psr, 4, 0);
	_LOG_(":M[4:0] = 0x%01x", mode);

	const char* mode_string = soc_core_trace_psr_mode_string[mode & 0x0f];

	if(mode_string)
		_LOG_(" (%s)", mode_string);

	if(pfn)
		_LOG_(" : %s", pfn);

	LOG_END();

	UNUSED(core);
}

void soc_core_trace_psr_change(soc_core_p core, const char* pfn, uint32_t saved_psr, uint32_t new_psr)
{
	soc_core_trace_psr(core, pfn, saved_psr);
	soc_core_trace_psr(core, pfn, new_psr);
}

void soc_core_trace_start(soc_core_p core)
{
	if(!core->trace)
		return;

	char flags[5], *dst = flags;
	
	*dst++ = IF_CPSR_F(C) ? 'C' : 'c';
	*dst++ = IF_CPSR_F(N) ? 'N' : 'n';
	*dst++ = IF_CPSR_F(V) ? 'V' : 'v';
	*dst++ = IF_CPSR_F(Z) ? 'Z' : 'z';
	*dst = 0;

	printf("%c(0x%08x(0x%08x), %s, %s(%c), ",
		(CPSR & SOC_CORE_PSR_T) ? 'T' : 'A',
		IP, IR, flags,
		CCx.s, CCx.e ? '>' : 'X');
}
