#pragma once

#if defined(__arm__) && !defined(__aarch64__)	

static uint32_t csx_test_arm_adcs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;

	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"adcs %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");

	return(res);

	UNUSED(t);
}

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

static void _test_flags_nz(csx_test_p t, uint32_t* psr, uint32_t res)
{
	BMAS(*psr, SOC_CORE_PSR_BIT_N, (((int32_t)res) < 0));
	BMAS(*psr, SOC_CORE_PSR_BIT_Z, (0 == res));

	UNUSED(t);
}

static void _test_flags_add(csx_test_p t, uint32_t* psr, uint32_t ir0, uint32_t ir1, uint32_t res)
{
	_test_flags_nz(t, psr, res);

	int cf = ir0 < ir1;
	int vf = ((signed)ir0) < ((signed)ir1);

	BMAS(*psr, SOC_CORE_PSR_BIT_C, cf);
	BMAS(*psr, SOC_CORE_PSR_BIT_V, vf);

	TRACE_PSR(*psr);
}

static void _test_flags_sub(csx_test_p t, uint32_t* psr, uint32_t ir0, uint32_t ir1, uint32_t res)
{
	_test_flags_nz(t, psr, res);

	int cf = ir0 < ir1;
	int vf = ((signed)ir0) < ((signed)ir1);

	BMAS(*psr, SOC_CORE_PSR_BIT_C, cf);
	BMAS(*psr, SOC_CORE_PSR_BIT_V, vf);

	TRACE_PSR(*psr);
}

static uint32_t _test_arm_adds_adcs(csx_test_p t, uint32_t* psr, uint32_t ir0, uint32_t ir1)
{
	_test_flags_add(t, psr, ir0, ir1, (ir0 + ir1));

	int cf = BEXT(*psr, SOC_CORE_PSR_BIT_C);
	uint32_t result = ir0 + ir1 + cf;
	
	_test_flags_add(t, psr, ir0, ir1, result);

	return(result);
}

static uint32_t csx_test_arm_adcs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	return(_test_arm_adds_adcs(t, psr, ir0, ir1));
}

static uint32_t csx_test_arm_adds_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_ands_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_bics_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_cmp_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_eors_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }
static uint32_t csx_test_arm_subs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1) { assert(0); }

#endif

