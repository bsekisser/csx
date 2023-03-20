#include "csx_test_arm_asm.h"

/* **** */

#include "soc_core_psr.h"

/* **** */

#include "csx_test.h"
#include "csx_test_utility.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

#include <stdint.h>

/* **** */

typedef uint32_t (*arm_test_fn)(uint32_t rn, uint32_t rm);

#define _test_assert(_test) \
	{ \
		if(!(_test)) { \
			LOG(#_test); \
			assert(_test); \
		} \
	}

/* **** */

static uint32_t _arm_adcs_rd_rn_rm(uint32_t rn, uint32_t rm) {
	uint32_t res = 0;

	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("adcs %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (res)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#endif

	return(res);
}

static uint32_t _arm_adds_rd_rn_rm(uint32_t rn, uint32_t rm) {
	uint32_t res = 0;

	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("adds %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (res)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#endif

	return(res);
}

static uint32_t _arm_ands_rd_rn_rm(uint32_t rn, uint32_t rm) {
	uint32_t res = 0;

	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("ands %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (res)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#endif

	return(res);
}

static uint32_t _arm_mrs_cpsr_fn(arm_test_fn fn, uint32_t *rd, uint32_t rn, uint32_t rm) {
	uint32_t psr = 0;
	uint32_t res = fn(rn, rm);

	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("mrs %[psr], CPSR\n\t"
			: [psr] "=r" (psr)
			:
			: "cc");
	#endif

	*rd = res;

	return(psr);
}

/* **** */

static void _test_arm_flags_nz(uint32_t* psr, uint32_t res) {
	BMAS(*psr, SOC_CORE_PSR_BIT_N, BEXT(res, 31));
	BMAS(*psr, SOC_CORE_PSR_BIT_Z, 0 == res);
}

static uint32_t _test_arm_adds_flags(uint32_t* psr, uint32_t ir0, uint32_t ir1, int carry_in) {
	uint32_t res = ir0 + ir1 + carry_in;

	_test_arm_flags_nz(psr, res);

	const uint32_t xvec = (ir0 ^ ir1);
	const uint32_t ovec = (ir0 ^ res) & ~xvec;

	const uint32_t cf = xvec ^ ovec ^ res;

	BMAS(*psr, SOC_CORE_PSR_BIT_C, BEXT(cf, 31));
	BMAS(*psr, SOC_CORE_PSR_BIT_V, BEXT(ovec, 31));
	
	return(res);
}

static uint32_t _test_arm_sub_flags(uint32_t* psr, uint32_t ir0, uint32_t ir1, int carry_in) {
	return(_test_arm_adds_flags(psr, ir0, ~ir1, carry_in));
}

/* **** */

uint32_t csx_test_arm_adcs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__)
	#if !defined(__aarch64__)
		uint32_t xpsr[2] = { 0, 0 };
		uint32_t xres[2] = { 0, 0 };

		xpsr[0] = _arm_mrs_cpsr_fn(_arm_adds_rd_rn_rm, &xres[0], ir0, ir1);
		xpsr[1] = _arm_mrs_cpsr_fn(_arm_adcs_rd_rn_rm, &xres[1], ir0, ir1);
	#endif

	uint32_t res = _test_arm_adds_flags(psr, ir0, ir1, 0);
	
	#if !defined(__aarch64__)
		_test_assert(res == xres[0]);
		assert(_test_cpsr_xpsr(t, *psr, xpsr[0]));
	#endif

	res = _test_arm_adds_flags(psr, ir0, ir1, BEXT(*psr, SOC_CORE_PSR_BIT_C));

	#if !defined(__aarch64__)
		_test_assert(res == xres[1]);
		assert(_test_cpsr_xpsr(t, *psr, xpsr[1]));
	#endif
#endif

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_adds_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__)
	#if !defined(__aarch64__)
		uint32_t xres = 0, xpsr = 0;
		
		xpsr = _arm_mrs_cpsr_fn(_arm_adds_rd_rn_rm, &xres, ir0, ir1);
	#endif

	uint32_t res = _test_arm_adds_flags(psr, ir0, ir1, 0);
	
	_test_assert(res == xres);
	assert(_test_cpsr_xpsr(t, *psr, xpsr));
#endif

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_ands_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;
	
#if defined(__arm__)
	#if !defined(__aarch64__)
		uint32_t xpsr = 0, xres = 0;

		xres = _arm_adds_rd_rn_rm(ir0, ir1);
		xpsr = _arm_mrs_cpsr_fn(_arm_ands_rd_rn_rm, &xres, ir0, ir1);
	#endif

	_test_arm_adds_flags(psr, ir0, ir1, 0);
	res = ir0 & ir1;
	_test_arm_flags_nz(psr, res);

	_test_assert(res == xres);
	assert(_test_cpsr_xpsr(t, *psr, xpsr));
#endif

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_bics_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
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

uint32_t csx_test_arm_cmp_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const uint32_t res = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	asm("cmp %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	(void)_test_arm_sub_flags(psr, ir0, ir1, 0);
#endif

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_eors_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
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

uint32_t csx_test_arm_subs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res = 0;

#if defined(__arm__) && !defined(__aarch64__)	
	asm("subs %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		: "cc");
#else
	res = _test_arm_sub_flags(psr, ir0, ir1, 0);
#endif

	return(res);

	UNUSED(t);
}
