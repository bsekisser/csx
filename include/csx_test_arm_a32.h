#pragma once

#if 1 && defined(__arm__) && !defined(__aarch64__)	

#include "csx_test_utility.h"
#include "soc_core_psr.h"
#include "log.h"

static void _test_flags_nz(csx_test_p t, uint32_t* psr, uint32_t res)
{
	BMAS(*psr, SOC_CORE_PSR_BIT_N, BEXT(res, 31));
//	BMAS(*psr, SOC_CORE_PSR_BIT_N, (((int32_t)res) < 0));
	BMAS(*psr, SOC_CORE_PSR_BIT_Z, (0 == res));

	UNUSED(t);
}

static void _test_flags_add(csx_test_p t, uint32_t* psr, uint32_t ir0, uint32_t ir1, uint32_t res)
{
	_test_flags_nz(t, psr, res);

//	int cf_in = BEXT(*psr, SOC_CORE_PSR_BIT_C);

	uint32_t cf = ir0 ^ ir1 ^ res;
//	uint32_t vf = ((ir0 & ir1) ^ res) ^ ((ir0 ^ ir1) & res);
	uint32_t vf = ((ir0 & ir1) & ~res);

	BMAS(*psr, SOC_CORE_PSR_BIT_C, BEXT(cf, 31));
	BMAS(*psr, SOC_CORE_PSR_BIT_V, BEXT(vf, 31));

	LOG("/* test -- 0x%08x + 0x%08x = 0x%08x */", ir0, ir1, res);
	TRACE_PSR(*psr);
}

#endif

static uint32_t csx_test_arm_adcs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t xres = 0, xpsr = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	#if !defined(__aarch64__)
		asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
			"mrs %[psr], CPSR\n\t"
			: [psr] "=r" (xpsr), [result] "=r" (xres)
			: [ir0] "r" (ir0), [ir1] "r" (ir1)
			: "cc");

		LOG("/* asm -- 0x%08x + 0x%08x = 0x%08x */", ir0, ir1, xres);
//		TRACE_PSR(xpsr)
//	#else
		uint32_t result = ir0 + ir1;
		_test_flags_add(t, psr, ir0, ir1, result);

		_assert_cpsr_xpsr(t, *psr, xpsr);
	#endif
#endif

#if defined(__arm__)
	#if !defined(__aarch64__)	
		asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
			"adcs %[result], %[ir0], %[ir1]\n\t"
			"mrs %[psr], CPSR\n\t"
			: [psr] "=r" (xpsr), [result] "=r" (xres)
			: [ir0] "r" (ir0), [ir1] "r" (ir1)
			: "cc");

		LOG("/* asm -- 0x%08x + 0x%08x = 0x%08x */", ir0, ir1, xres);
//		TRACE_PSR(xpsr)
//	#else
		int cf = BEXT(*psr, SOC_CORE_PSR_BIT_C);
		result = ir0 + ir1 + cf;
		
		_test_flags_add(t, psr, ir0, ir1, result);

		_assert_cpsr_xpsr(t, *psr, xpsr);
	#endif
#endif

#if 0
	*psr = xpsr;
	return(xres);
#else
	return(result);
#endif

	UNUSED(t);
}

#if 0 && defined(__arm__) && !defined(__aarch64__)	

static uint32_t csx_test_arm_adds_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_ands_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"ands %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_bics_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"bics %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_cmp_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const uint32_t res = 0;

	asm("cmp %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_eors_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"eors %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_subs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;
	
	asm("subs %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");

	return(res);

	UNUSED(t);
}

#else

#include "csx_test_utility.h"
#include "soc_core_psr.h"
#include "log.h"

static void _test_flags_sub(csx_test_p t, uint32_t* psr, uint32_t ir0, uint32_t ir1, uint32_t res)
{
	_test_flags_nz(t, psr, res);

	int cf = ir0 < ir1;
	int vf = ((signed)ir0) < ((signed)ir1);

	BMAS(*psr, SOC_CORE_PSR_BIT_C, cf);
	BMAS(*psr, SOC_CORE_PSR_BIT_V, vf);

	LOG("/* %#08x + %#08x = %#08x */", ir0, ir1, res);
	TRACE_PSR(*psr);
}

static uint32_t csx_test_arm_adds_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_ands_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_bics_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_cmp_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_eors_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_subs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }

#endif

