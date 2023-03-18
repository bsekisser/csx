#pragma once

/* **** */

#include "soc_core_psr.h"

/* **** */

#include "csx_test.h"

/* **** */

#include "bitfield.h"

/* **** */

#include <stdint.h>

/* **** */

static void _test_arm_flags_nz(uint32_t* psr, uint32_t res) {
	BMAS(*psr, SOC_CORE_PSR_BIT_N, BEXT(res, 31));
	BMAS(*psr, SOC_CORE_PSR_BIT_Z, 0 == res);
}

static uint32_t _test_arm_add_flags(uint32_t* psr, uint32_t ir0, uint32_t ir1, int carry_in) {
	uint32_t res = ir0 + ir1 + carry_in;

	_test_arm_flags_nz(psr, res);

	uint carry = ir0 ^ ir1 ^ res;
	uint cav = ir0 & ir1;
	uint ov = (cav ^ res) || (cav ^ ~res);

	BMAS(*psr, SOC_CORE_PSR_BIT_C, BEXT(carry, 31));
	BMAS(*psr, SOC_CORE_PSR_BIT_V, BEXT(ov, 31));

	return(res);
}

static uint32_t csx_test_arm_adcs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"adcs %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	(void)_test_arm_add_flags(psr, ir0, ir1, 0);
	res = _test_arm_add_flags(psr, ir0, ir1, BEXT(*psr, SOC_CORE_PSR_BIT_C));
#endif

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_adds_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	asm("adds %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	res = _test_arm_add_flags(psr, ir0, ir1, 0);
#endif

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_ands_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;
	
#if defined(__arm__) && !defined(__aarch64__)	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"ands %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	res = ir0 & ir1;
	_test_arm_flags_nz(psr, res);
#endif

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_bics_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"bics %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	res = ir0 & ~ir1;
	_test_arm_flags_nz(psr, res);
#endif

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_cmp_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const uint32_t res = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	asm("cmp %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	(void)_test_arm_add_flags(psr, ir0, -ir1, 0);
#endif

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_eors_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"eors %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	res = ir0 ^ ir1;
	_test_arm_flags_nz(psr, res);
#endif

	return(res);

	UNUSED(t);
}

static uint32_t csx_test_arm_subs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	asm("subs %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	res = _test_arm_add_flags(psr, ir0, -ir1, 0);
#endif

	return(res);

	UNUSED(t);
}
