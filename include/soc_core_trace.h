#pragma once

/* **** */

#include "csx.h"

/* **** */

#include "soc_core.h"

/* **** */

#if 1
	#define CORE_T(_x) _x
	#define CORE_TRACE(_f, args...) \
		do { \
			if(core->trace) \
			{ \
				printf("%c(0x%08x(0x%08x), %s(%c), " _f ")\n", \
					(CPSR & SOC_CORE_PSR_T) ? 'T' : 'A', \
					IP, IR, \
					CCx.s, CCx.e ? '>' : 'X', \
					## args); \
			} \
		}while(0);
#else
	#define CORE_T(_x)
	#define CORE_TRACE(_f, args...)
#endif

#define CORE_TRACE_LINK(_lr)
#define CORE_TRACE_BRANCH(_pc)
#define CORE_TRACE_BRANCH_CC(_pc)
#define CORE_TRACE_THUMB

void soc_core_trace_psr(soc_core_p core, const char* pfn, uint32_t psr);
void soc_core_trace_psr_change(soc_core_p core, const char* pfn, uint32_t saved_psr, uint32_t new_psr);
