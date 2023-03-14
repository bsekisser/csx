#pragma once

/* **** */

#include "csx_test.h"
#include "soc_core_psr.h"

/* **** */

void _assert_cpsr_xpsr(csx_test_p t, uint cpsr, uint xpsr);
void _assert_cpsr_xpsr_mask(csx_test_p t, uint cpsr, uint xpsr, uint mask);
void _assert_nzc(csx_test_p t, int n, int z, int c);
void _assert_nzcv(csx_test_p t, int n, int z, int c, int v);
void _cxx(csx_test_p t, uint32_t value, size_t size);
uint32_t _test_value(uint8_t i);

/* **** */

uint32_t pc(csx_test_p t);

/* **** */

#define ASSERT_LOG(_test, _f, ...) \
	({ \
		if(!(_test)) { \
			LOG(#_test " : " _f, ## __VA_ARGS__); \
			assert(_test); \
		} \
	})

#define TRACE_PSR(psr) \
	do { \
		LOG(#psr " -- N = %1u, Z = %1u, C = %1u, V = %1u -- 0x%08x", \
			!!(psr & SOC_CORE_PSR_N), !!(psr & SOC_CORE_PSR_Z), \
			!!(psr & SOC_CORE_PSR_C), !!(psr & SOC_CORE_PSR_V), psr); \
	}while(0);
