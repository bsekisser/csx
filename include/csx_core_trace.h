#pragma once

#include <stdio.h>

#if 0
	#define T(_x) _x
		#ifndef TRACE
			#define TRACE(_f, args...) \
				printf("// %s:%u >>" _f "\n", __FUNCTION__, __LINE__, ## args);
		#endif
	#define CORE_T(_x) _x
	#define CORE_TRACE(_f, args...) \
		do { \
			if(csx_trace_core(core)) \
			{ \
				printf("%c(0x%08x(0x%08x), %s(%c), " _f ")\n", \
					(CPSR & CSX_PSR_T) ? 'T' : 'A', \
					IP, opcode, \
					core->ccs, cce ? '>' : 'X', \
					## args); \
			} \
		}while(0);
#else
//	#define T(_x)
//	#define TRACE(_f, args...)
//	#define CORE_T(_x)
//	#define CORE_TRACE(_f, args...)
#endif

#if 1
	#define CORE_T(_x) _x
	#define CORE_TRACE(_f, args...) \
		do { \
			if(csx_trace_core(core)) \
			{ \
				printf("%c(0x%08x(0x%08x), %s(%c), " _f ")\n", \
					(CPSR & CSX_PSR_T) ? 'T' : 'A', \
					IP, opcode, \
					core->ccs, cce ? '>' : 'X', \
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

int csx_trace_core(csx_core_p csx);

void csx_trace_psr(csx_core_p core, const char* pfn, uint32_t psr);
void csx_trace_psr_change(csx_core_p core, const char* pfn, uint32_t saved_psr, uint32_t new_psr);
void csx_trace_inst_dpi(csx_core_p core, uint32_t opcode, csx_dpi_p dpi, uint8_t cce);
void csx_trace_inst_ldst(csx_core_p core, uint32_t opcode, csx_ldst_p ls, uint8_t cce);

/* csx_core_disasm.h */

void csx_core_disasm(csx_core_p core, uint32_t address, uint32_t opcode);
