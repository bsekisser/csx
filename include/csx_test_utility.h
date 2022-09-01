#pragma once

/* **** */

#include "csx_test.h"
#include "soc_core_psr.h"

/* **** */

void _assert_cpsr_xpsr(csx_test_p t, uint cpsr, uint xpsr);
void _assert_nzcv(csx_test_p t, int n, int z, int c, int v);
void _cxx(csx_test_p t, uint32_t value, uint8_t size);
uint32_t _test_value(uint8_t i);

/* **** */

uint32_t pc(csx_test_p t);

/* **** */

#define TRACE_PSR(psr) \
	do { \
		LOG("N = %1u, Z = %1u, C = %1u, V = %1u", \
			!!(psr & SOC_CORE_PSR_N), !!(psr & SOC_CORE_PSR_Z), \
			!!(psr & SOC_CORE_PSR_C), !!(psr & SOC_CORE_PSR_V)); \
	}while(0);
