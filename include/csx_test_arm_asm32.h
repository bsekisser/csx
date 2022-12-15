#include <stdint.h>

static uint32_t csx_test_arm_adcs_asm(uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__) && !defined(__aarch64__)
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"adcs %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	return(res);
#else
	return(0xdeadbeef);
#endif
}

static uint32_t csx_test_arm_adds_asm(uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__) && !defined(__aarch64__)
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	return(res);
#else
	return(0xdeadbeef);
#endif
}

static uint32_t csx_test_arm_ands_asm(uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__) && !defined(__aarch64__)
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"ands %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	return(res);
#else
	return(0xdeadbeef);
#endif
}

static uint32_t csx_test_arm_bics_asm(uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__) && !defined(__aarch64__)
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"bics %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	return(res);
#else
	return(0xdeadbeef);
#endif
}

static uint32_t csx_test_arm_cmp_asm(uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__) && !defined(__aarch64__)
	const uint32_t res = 0;

	asm("cmp %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	return(res);
#else
	return(0xdeadbeef);
#endif
}

static uint32_t csx_test_arm_eors_asm(uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__) && !defined(__aarch64__)
	uint32_t res = 0;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t" /* << ensure predictable psr result */
		"eors %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	return(res);
#else
	return(0xdeadbeef);
#endif
}

static void csx_test_arm_ldmda_asm(uint32_t* asp, uint32_t* r)
{
#if defined(__arm__) && !defined(__aarch64__)
	asm(
		"ldmda %[stack]!, {r1, r2, r3, r4}\n\t"
		"mov %[r1], r1\n\t"
		"mov %[r2], r2\n\t"
		"mov %[r3], r3\n\t"
		"mov %[r4], r4\n\t"
		: [stack] "+r" (asp[1])
			, [r1] "=r" (r[0])
			, [r2] "=r" (r[1])
			, [r3] "=r" (r[2])
			, [r4] "=r" (r[3]) ::
		"r1", "r2", "r3", "r4"
		);
#else
	exit(-1);
#endif
}

static void csx_test_arm_ldmdb_asm(uint32_t* asp, uint32_t* r)
{
#if defined(__arm__) && !defined(__aarch64__)
	asm(
		"ldmdb %[stack]!, {r1, r2, r3, r4}\n\t"
		"mov %[r1], r1\n\t"
		"mov %[r2], r2\n\t"
		"mov %[r3], r3\n\t"
		"mov %[r4], r4\n\t"
		: [stack] "+r" (asp[1])
			, [r1] "=r" (r[0])
			, [r2] "=r" (r[1])
			, [r3] "=r" (r[2])
			, [r4] "=r" (r[3]) ::
		"r1", "r2", "r3", "r4"
		);
#else
	exit(-1);
#endif
}

static void csx_test_arm_ldmia_asm(uint32_t* asp, uint32_t* r)
{
#if defined(__arm__) && !defined(__aarch64__)
	asm(
		"ldmia %[stack]!, {r1, r2, r3, r4}\n\t"
		"mov %[r1], r1\n\t"
		"mov %[r2], r2\n\t"
		"mov %[r3], r3\n\t"
		"mov %[r4], r4\n\t"
		: [stack] "+r" (asp[1])
			, [r1] "=r" (r[0])
			, [r2] "=r" (r[1])
			, [r3] "=r" (r[2])
			, [r4] "=r" (r[3]) ::
		"r1", "r2", "r3", "r4"
		);
#else
	exit(-1);
#endif
}


static void csx_test_arm_ldmib_asm(uint32_t* asp, uint32_t* r)
{
#if defined(__arm__) && !defined(__aarch64__)
	asm(
		"ldmib %[stack]!, {r1, r2, r3, r4}\n\t"
		"mov %[r1], r1\n\t"
		"mov %[r2], r2\n\t"
		"mov %[r3], r3\n\t"
		"mov %[r4], r4\n\t"
		: [stack] "+r" (asp[1])
			, [r1] "=r" (r[0])
			, [r2] "=r" (r[1])
			, [r3] "=r" (r[2])
			, [r4] "=r" (r[3]) ::
		"r1", "r2", "r3", "r4"
		);
#else
	exit(-1);
#endif
}

static uint32_t csx_test_arm_subs_asm(uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
#if defined(__arm__) && !defined(__aarch64__)
	uint32_t res = 0;
	
	asm("subs %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	return(res);
#else
	return(0xdeadbeef);
#endif
}
