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

typedef struct return_t* return_p;
typedef struct return_t {
	uint32_t result;
	uint32_t psr;
}return_t;

typedef void (*arm_test_fn)(return_p p2rt, uint32_t rn, uint32_t rm);

#define _test_assert(_test) \
	{ \
		if(!(_test)) { \
			LOG(#_test); \
			assert(_test); \
		} \
	}

/* **** */

static void _arm_adcs_rd_rn_rm(return_p p2rt, uint32_t rn, uint32_t rm) {
	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("adcs %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (p2rt->result)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#else
		p2rt->result = rn + rm + BEXT(p2rt->psr, SOC_CORE_PSR_BIT_C);
	#endif
}

static void _arm_adds_rd_rn_rm(return_p p2rt, uint32_t rn, uint32_t rm) {
	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("adds %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (p2rt->result)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#else
		p2rt->result = rn + rm;
	#endif
}

static void _arm_ands_rd_rn_rm(return_p p2rt, uint32_t rn, uint32_t rm) {
	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("ands %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (p2rt->result)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#else
		p2rt->result = rn & rm;
	#endif
}

static void _arm_bics_rd_rn_rm(return_p p2rt, uint32_t rn, uint32_t rm) {
	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("bics %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (p2rt->result)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#else
		p2rt->result = rn & ~rm;
	#endif
}

static void _arm_cmps_rd_rn_rm(return_p p2rt, uint32_t rn, uint32_t rm) {
	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("cmp %[rn], %[rm]\n\t"
			: /* output(s) */
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");

		UNUSED(p2rt);
	#else
		p2rt->result = rn - rm;
	#endif
}

static void _arm_eors_rd_rn_rm(return_p p2rt, uint32_t rn, uint32_t rm) {
	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("eors %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (p2rt->result)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#else
		p2rt->result = rn ^ rm;
	#endif
}

static void _arm_mrs_cpsr_fn(arm_test_fn fn, return_p p2rt, uint32_t rn, uint32_t rm) {
	fn(p2rt, rn, rm);

	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("mrs %[psr], CPSR\n\t"
			: [psr] "=r" (p2rt->psr)
			: /* input(s) */
			: "cc");
	#endif
}

static void _arm_subs_rd_rn_rm(return_p p2rt, uint32_t rn, uint32_t rm) {
	#if defined(__arm__) && !defined(__aarch64__)
		asm volatile("subs %[result], %[rn], %[rm]\n\t"
			: [result] "=r" (p2rt->result)
			: [rn] "r" (rn), [rm] "r" (rm)
			: "cc");
	#else
		p2rt->result = rn - rm;
	#endif
}

/* **** */

static void _test_arm_flags_nz(uint32_t* psr, uint32_t res) {
	BMAS(*psr, SOC_CORE_PSR_BIT_N, BEXT(res, 31));
	BMAS(*psr, SOC_CORE_PSR_BIT_Z, 0 == res);
}

static uint32_t _test_arm_add_sub_flags(uint32_t* psr, uint32_t res, uint32_t ir0, uint32_t ir1) {
	_test_arm_flags_nz(psr, res);

	const uint32_t xvec = (ir0 ^ ir1);
	const uint32_t ovec = (ir0 ^ res) & ~xvec;

	const uint32_t cf = xvec ^ ovec ^ res;

	BMAS(*psr, SOC_CORE_PSR_BIT_C, BEXT(cf, 31));
	BMAS(*psr, SOC_CORE_PSR_BIT_V, BEXT(ovec, 31));
	
	return(res);
}

#if defined(__arm__) && !defined(__aarch64__)
	#define _arm_assert(_test) assert(_test)
#else
	#define _arm_assert(_test)
#endif

static uint32_t _test_arm_adcs_flags(uint32_t* psr, uint32_t ir0, uint32_t ir1, uint32_t psr_c) {
	uint32_t res = ir0 + ir1 + BEXT(psr_c, SOC_CORE_PSR_BIT_C);
	
	return(_test_arm_add_sub_flags(psr, res, ir0, ir1));
}

static uint32_t _test_arm_adds_flags(uint32_t* psr, uint32_t ir0, uint32_t ir1) {
	uint32_t res = ir0 + ir1;
	
	return(_test_arm_add_sub_flags(psr, res, ir0, ir1));
}

static uint32_t _test_arm_subs_flags(uint32_t* psr, uint32_t ir0, uint32_t ir1) {
	uint32_t res = ir0 - ir1;
	
	return(_test_arm_add_sub_flags(psr, res, ir0, ~ir1));
}

/* **** */

uint32_t csx_test_arm_adcs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	return_t xrt[2];

	_arm_mrs_cpsr_fn(_arm_adds_rd_rn_rm, &xrt[0], ir0, ir1);
	_arm_mrs_cpsr_fn(_arm_adcs_rd_rn_rm, &xrt[1], ir0, ir1);

	uint32_t res = _test_arm_adds_flags(psr, ir0, ir1);
	_arm_assert(res == xrt[0].result);
	_arm_assert(_test_cpsr_xpsr(t, *psr, xrt[0].psr));

	res = _test_arm_adcs_flags(psr, ir0, ir1, *psr);
	_arm_assert(res == xrt[1].result);
	_arm_assert(_test_cpsr_xpsr(t, *psr, xrt[1].psr));

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_adds_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	return_t xrt;

	_arm_mrs_cpsr_fn(_arm_adds_rd_rn_rm, &xrt, ir0, ir1);

	uint32_t res = _test_arm_adds_flags(psr, ir0, ir1);
	_arm_assert(res == xrt.result);
	_arm_assert(_test_cpsr_xpsr(t, *psr, xrt.psr));

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_ands_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	return_t xrt;

	_arm_adds_rd_rn_rm(&xrt, ir0, ir1);
	_arm_mrs_cpsr_fn(_arm_ands_rd_rn_rm, &xrt, ir0, ir1);

	_test_arm_adds_flags(psr, ir0, ir1);
	const uint32_t res = ir0 & ir1;
	_test_arm_flags_nz(psr, res);

	_arm_assert(res == xrt.result);
	_arm_assert(_test_cpsr_xpsr(t, *psr, xrt.psr));

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_bics_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	return_t xrt;

	_arm_adds_rd_rn_rm(&xrt, ir0, ir1);
	_arm_mrs_cpsr_fn(_arm_bics_rd_rn_rm, &xrt, ir0, ir1);

	_test_arm_adds_flags(psr, ir0, ir1);
	const uint32_t res = ir0 & ~ir1;
	_test_arm_flags_nz(psr, res);

	_arm_assert(res == xrt.result);
	_arm_assert(_test_cpsr_xpsr(t, *psr, xrt.psr));

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_cmp_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	return_t xrt;

	_arm_mrs_cpsr_fn(_arm_cmps_rd_rn_rm, &xrt, ir0, ir1);
//	_arm_mrs_cpsr_fn(_arm_subs_rd_rn_rm, &xrt, ir0, ir1);

	const uint32_t res = _test_arm_subs_flags(psr, ir0, ir1);

	if(1) {
		_arm_assert(_test_cpsr_xpsr(t, *psr, xrt.psr));
		return(0);
	} else {
		if(_test_cpsr_xpsr(t, *psr, xrt.psr)) {
			LOG(" ir0 = 0x%08x,  ir1 = 0x%08x",	ir0, ir1);
			LOG("xrt.result = 0x%08x, xrt.psr = 0x%08x", xrt.result, xrt.psr);
			LOG("tres = 0x%08x, tpsr = 0x%08x", res, *psr);
		}
	}

	return(res);
	
	UNUSED(t);
}

uint32_t csx_test_arm_eors_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	return_t xrt;

	_arm_adds_rd_rn_rm(&xrt, ir0, ir1);
	_arm_mrs_cpsr_fn(_arm_eors_rd_rn_rm, &xrt, ir0, ir1);

	_test_arm_adds_flags(psr, ir0, ir1);
	const uint32_t res = ir0 ^ ir1;
	_test_arm_flags_nz(psr, res);

	_arm_assert(res == xrt.result);
	_arm_assert(_test_cpsr_xpsr(t, *psr, xrt.psr));

	return(res);

	UNUSED(t);
}

uint32_t csx_test_arm_subs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	return_t xrt;
	_arm_mrs_cpsr_fn(_arm_subs_rd_rn_rm, &xrt, ir0, ir1);

	const uint32_t res = _test_arm_subs_flags(psr, ir0, ir1);

	if(1) {
		_arm_assert(res == xrt.result);
		_arm_assert(_test_cpsr_xpsr(t, *psr, xrt.psr));
	} else {
		if((res != xrt.result) ||
			!_test_cpsr_xpsr(t, *psr, xrt.psr))
		{
			LOG("xrt.result = 0x%08x, xrt.psr = 0x%08x", xrt.result, xrt.psr);
			LOG("tres = 0x%08x, tpsr = 0x%08x", res, *psr);
		}
	}

	return(res);

	UNUSED(t);
}
