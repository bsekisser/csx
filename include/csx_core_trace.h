#if 1
	#define CORE_T(_x) _x
	#define CORE_TRACE(_f, args...) \
		printf("I(0x%08x, %s, /* %c 0x%08x */ " _f ")\n", \
			core->pc, core->ccs, cce ? '>' : '|', opcode, ## args);
#else
	#define CORE_T(_x) 0
	#define CORE_TRACE(_f, args...)
#endif

void csx_trace_psr(csx_core_p core, const char* pfn, uint32_t psr);
void csx_trace_psr_change(csx_core_p core, const char* pfn, uint32_t saved_psr, uint32_t new_psr);
void csx_trace_inst_dpi(csx_core_p core, uint32_t opcode, csx_dpi_p dpi, uint8_t cce);
void csx_trace_inst_ldst(csx_core_p core, uint32_t opcode, csx_ldst_p ls, uint8_t cce);

/* csx_core_disasm.h */

void csx_core_disasm(csx_core_p core, uint32_t address, uint32_t opcode);
