#include "soc_core_trace.h"

/* **** */

#include "bitfield.h"
#include "log.h"

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

void soc_core_trace_psr(soc_core_p core, const char* pfn, uint32_t psr)
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
	
	const char* mode_string = soc_core_trace_psr_mode_string[mode & 0x0f];
	if(!mode_string)
		mode_string = "";

	LOG("%s (%s) : %s", tout, mode_string, pfn ? pfn : "");
}

void soc_core_trace_psr_change(soc_core_p core, const char* pfn, uint32_t saved_psr, uint32_t new_psr)
{
	soc_core_trace_psr(core, pfn, saved_psr);
	soc_core_trace_psr(core, pfn, new_psr);
}
