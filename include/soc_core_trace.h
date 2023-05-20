#pragma once

/* **** */

#include "csx.h"

/* **** */

#include "soc_core.h"

/* **** */

#if 1
	#define CORE_T(_x) _x
	#define CORE_TRACE(_f, ...) \
		soc_core_trace(core, _f, ##__VA_ARGS__)
	#define CORE_TRACE_END() \
		soc_core_trace_end(core)
	#define CORE_TRACE_START() \
		soc_core_trace_start(core)
	#define _CORE_TRACE_(_f, ...) \
		soc_core_trace_out(core, _f, ##__VA_ARGS__)
#else
	#define CORE_T(_x)
	#define CORE_TRACE(_f, ...) ({})
	#define CORE_TRACE_END() ({})
	#define CORE_TRACE_START() ({})
	#define _CORE_TRACE_(_f, ...) ({})
#endif

#define CORE_TRACE_LINK(_lr) ({})
#define CORE_TRACE_BRANCH(_pc) ({})
#define CORE_TRACE_BRANCH_CC(_pc) ({})
#define CORE_TRACE_THUMB ({})

void soc_core_trace(soc_core_p core, const char* format, ...);
void soc_core_trace_dump_regs(soc_core_p core);
void soc_core_trace_end(soc_core_p core);
void soc_core_trace_out(soc_core_p core, const char* format, ...);
void soc_core_trace_psr(soc_core_p core, const char* pfn, uint32_t psr);
void soc_core_trace_psr_change(soc_core_p core, const char* pfn, uint32_t saved_psr, uint32_t new_psr);
void soc_core_trace_start(soc_core_p core);
