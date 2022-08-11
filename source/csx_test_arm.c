#include "csx.h"
#include "csx_core.h"
#include "csx_test.h"
#include "csx_test_utility.h"

#include "csx_test_arm_inst.h"

static void _assert_cpsr_xpsr(csx_test_p t, uint cpsr, uint xpsr)
{
	cpsr &= mlBF(31, 28);
	xpsr &= mlBF(31, 28);
	
	assert(cpsr == xpsr);
}

static void _assert_nzcv(csx_test_p t, int n, int z, int c, int v)
{
	csx_core_p core = t->csx->core;
	
	assert(n == BEXT(CPSR, CSX_PSR_BIT_N));
	assert(z == BEXT(CPSR, CSX_PSR_BIT_Z));
	assert(c == BEXT(CPSR, CSX_PSR_BIT_C));
	assert(v == BEXT(CPSR, CSX_PSR_BIT_V));
}

static inline uint32_t epc(csx_test_p t)
{
	return(pc(t) + 8);
}

static inline uint32_t eao(csx_test_p t, int32_t ieao)
{
	/* (((offset - 8) >> 2) & 0x00ffffff) */

	if(0 > ieao)
		ieao--;

	uint32_t ea = (ieao << 2) - 4;
	
	if(0) LOG("ea = 0x%08x", ea);
	
	return(ea);
}

#define TRACE_PSR(psr) \
	do { \
		LOG("N = %1u, Z = %1u, C = %1u, V = %1u", \
			!!(psr & CSX_PSR_N), !!(psr & CSX_PSR_Z), \
			!!(psr & CSX_PSR_C), !!(psr & CSX_PSR_V)); \
	}while(0);

static void csx_test_arm_fn(csx_test_p t)
{
	uint32_t r[6];

	for(int i = 0; i < 6; i++)
		r[i] = 0;

	uint32_t psr;
	
	r[5] = 1;
	r[5] <<= 29;
	r[3] = r[5] + 0;
	r[4] = 0xe59ff000;
	r[0] = 0;
	r[3] += 0x64;
		
	LOG("r0 = 0x%08x, r1 = 0x%08x, r2 = 0x%08x", r[0], r[1], r[2]);
	LOG("r3 = 0x%08x, r4 = 0x%08x, r5 = 0x%08x", r[3], r[4], r[5]);

	int count = 0x09;

	do{
		r[1] = r[0] + r[5];
		r[2] = r[0] + r[3];
		r[2] = r[2] - r[1];
		r[2] -= 0x08;
		r[2] |= r[4];
		r[0] += 0x04;

		LOG("r0 = 0x%08x, r1 = 0x%08x, r2 = 0x%08x", r[0], r[1], r[2]);
		LOG("r3 = 0x%08x, r4 = 0x%08x, r5 = 0x%08x", r[3], r[4], r[5]);

		asm("cmp %[r0], #0x1c\n\t"
			"mrs %[psr], CPSR\n\t"
			: [psr] "=r" (psr)
			: [r0] "r" (r[0])
			: "r0");

		int blo = !(psr & CSX_PSR_C);

		LOG("blo = %u", blo);

		TRACE_PSR(psr);
	}while(--count);
}

static uint32_t csx_test_arm_add_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res;
	
	asm("adds %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	LOG("psr = 0x%08x, res = 0x%08x", *psr, res);
	
	TRACE_PSR(*psr);
	return(res);
}

static uint32_t csx_test_arm_sub_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	uint32_t res;
	
	asm("subs %[result], %[ir0], %[ir1]\n\t"
		"mrs %[psr], CPSR\n\t"
		: [psr] "=r" (*psr), [result] "=r" (res)
		: [ir0] "r" (ir0), [ir1] "r" (ir1)
		:);

	LOG("psr = 0x%08x, res = 0x%08x", *psr, res);
	
	TRACE_PSR(*psr);
	return(res);
}

static uint32_t csx_test_arm_add_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	csx_core_p core = t->csx->core;
	uint32_t res = 0;

	csx_reg_set(core, 0, ir0);
	csx_reg_set(core, 1, ir1);
	
	t->start_pc = t->pc = 0x10000000;
	arm_adds_rn_rd_sop(t, 0, 0, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 3);

	*psr = CPSR;

	res = csx_reg_get(core, 0);
	LOG("psr = 0x%08x, res = 0x%08x", CPSR, res);
	
	TRACE_PSR(CPSR);

	return(res);
}

static uint32_t csx_test_arm_sub_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	csx_core_p core = t->csx->core;
	uint32_t res = 0;

	csx_reg_set(core, 0, ir0);
	csx_reg_set(core, 1, ir1);
	
	t->start_pc = t->pc = 0x10000000;
	arm_subs_rn_rd_sop(t, 0, 0, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 3);

	*psr = CPSR;

	res = csx_reg_get(core, 0);
	LOG("psr = 0x%08x, res = 0x%08x", CPSR, res);
	
	TRACE_PSR(CPSR);

	return(res);
}

static void csx_test_arm_add(csx_test_p t)
{
//	csx_core_p core = t->csx->core;
	t->start_pc = t->pc = 0x10000000;

	uint32_t res, xres;
	uint32_t xpsr, cpsr;

	xres = csx_test_arm_add_asm(t, &xpsr, ~0, 1);
	res = csx_test_arm_add_inst(t, &cpsr, ~0, 1);
	
	assert(xres == res);
	_assert_cpsr_xpsr(t, cpsr, xpsr);
	_assert_nzcv(t, 0, 1, 1, 0);
	
	xres = csx_test_arm_add_asm(t, &xpsr, 12, 1);
	res = csx_test_arm_add_inst(t, &cpsr, 12, 1);

	assert(13 == res);
	_assert_cpsr_xpsr(t, cpsr, xpsr);
	_assert_nzcv(t, 0, 0, 0, 0);
	
	xres = csx_test_arm_sub_asm(t, &xpsr, 13, 12);
	res = csx_test_arm_sub_inst(t, &cpsr, 13, 12);

	assert(1 == res);
	_assert_cpsr_xpsr(t, cpsr, xpsr);
	_assert_nzcv(t, 0, 0, 1, 0);

	xres = csx_test_arm_sub_asm(t, &xpsr, 12, 13);
	res = csx_test_arm_sub_inst(t, &cpsr, 12, 13);

	assert(-1 == res);
	_assert_cpsr_xpsr(t, cpsr, xpsr);
	_assert_nzcv(t, 1, 0, 0, 0);
	
	xres = csx_test_arm_sub_asm(t, &xpsr, 0x1c, 0x1c);
	res = csx_test_arm_sub_inst(t, &cpsr, 0x1c, 0x1c);

	assert(0 == res);
	_assert_cpsr_xpsr(t, cpsr, xpsr);
	_assert_nzcv(t, 0, 1, 1, 0);

	xres = csx_test_arm_sub_asm(t, &xpsr, 0x1d, 0x1c);
	res = csx_test_arm_sub_inst(t, &cpsr, 0x1d, 0x1c);

	assert(1 == res);
	_assert_cpsr_xpsr(t, cpsr, xpsr);
	_assert_nzcv(t, 0, 0, 1, 0);
}

static void csx_test_arm_b(csx_test_p t)
{
	csx_core_p core = t->csx->core;

	uint32_t offset = eao(t, 3);
	uint32_t new_pc = epc(t) + offset;
	
	if(0) LOG("pc = 0x%08x, start_pc = 0x%08x, offset == 0x%08x, new_pc = 0x%08x",
		pc(t), t->start_pc, offset, new_pc);
	
	arm_b(t, offset);
	t->start_pc = t->pc = csx_test_run(t, 1);

	if(0) LOG("pc = 0x%08x", pc(t));

	assert(new_pc == PC);

	offset = eao(t, -3);
	new_pc = epc(t) + offset;
	
	if(0) LOG("pc = 0x%08x, start_pc = 0x%08x, offset == 0x%08x, new_pc = 0x%08x",
		pc(t), t->start_pc, offset, new_pc);

	arm_bl(t, offset);
	uint32_t expect_lr = pc(t);

	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(new_pc == PC);
	assert(expect_lr == LR);
	
	if(0) LOG("start_pc = 0x%08x, pc(t) = 0x%08x, LR = 0x%08x", t->start_pc, pc(t), LR);
	
	offset = eao(t, 1) | 2;
	new_pc = epc(t) + offset;
	
	arm_blx(t, offset);
	expect_lr = pc(t);
	
	t->start_pc = t->pc = csx_test_run(t, 1) & ~3;
	assert(new_pc == PC);
	assert(expect_lr == LR);
	assert(CPSR & CSX_PSR_BIT_T);

	if(0) LOG("start_pc = 0x%08x, pc(t) = 0x%08x, LR = 0x%08x", t->start_pc, pc(t), LR);

	offset = eao(t, 2) | 2;
	new_pc = epc(t) + offset;
	
	arm_blx(t, offset);
	expect_lr = pc(t);
	
	t->start_pc = t->pc = csx_test_run(t, 1) & ~3;
	assert(new_pc == PC);
	assert(expect_lr == LR);
	assert(CPSR & CSX_PSR_BIT_T);

	if(0) LOG("start_pc = 0x%08x, pc(t) = 0x%08x, LR = 0x%08x", t->start_pc, pc(t), LR);
}

static inline uint32_t _test_value(uint8_t i)
{
	uint32_t test_value = i | i << 16;

	test_value |= test_value << 4;
	test_value |= test_value << 8;

	return(test_value);
}

typedef struct ldstm_t* ldstm_p;
typedef struct ldstm_t {
	uint32_t						stack[16];
	uint32_t						r[4];

	uint32_t*						asp[2];
	uint32_t						esp[2];
}ldstm_t;

static void csx_test_arm_ldstm_assert_check(csx_test_p t,
	ldstm_p l,
	uint tvs,
	uint rvs)
{
	uint32_t asp_diff = (uint32_t)l->asp[1] - (uint32_t)l->asp[0];
	uint32_t esp_diff = (uint32_t)l->esp[1] - (uint32_t)l->esp[0];

	if(0) LOG("esp_in = 0x%08x, esp_out 0x%08x, esp_diff = 0x%08x",
		(uint32_t)l->esp[0], (uint32_t)l->esp[1], esp_diff);

	assert(asp_diff == esp_diff);
	
	for(int i = 0; i < 16; i++)
	{
		uint32_t espv = 0x10001000 + (i << 2);
		uint32_t esiv = csx_soc_read(t->csx, espv, sizeof(uint32_t)); 
		assert(l->stack[i] == esiv);
	}
	
	for(int i = 0; i < 4; i++) {
		uint32_t rv = csx_reg_get(t->csx->core, rvs + i);
		if(0) LOG("r[%02x] = 0x%08x", i, rv);
		
		assert(_test_value(tvs + i) == rv);
	}
}

static void csx_test_arm_ldstm_setup_stack(csx_test_p t, ldstm_p l, uint spat)
{
	l->esp[0] = 0x10001000 + (spat << 2);
	l->esp[1] = l->esp[0];

	for(int i = 0; i < 16; i++) {
		uint32_t tvi = _test_value(i);
		
		l->stack[i] = tvi;

		csx_soc_write(t->csx, 0x10001000 + (i << 2), tvi, sizeof(uint32_t));
	}
	
	l->asp[0] = &l->stack[spat];
	l->asp[1] = l->asp[0];
}

static void csx_test_arm_ldm_dump_stack(
	csx_test_p t,
	ldstm_p l)
{
	uint32_t sp_diff = (uint32_t)l->asp[1] - (uint32_t)l->asp[0];

	if(0) LOG("asp_in = 0x%08x, asp_out 0x%08x, asp_diff = 0x%08x",
		(uint32_t)l->asp[0], (uint32_t)l->asp[1], sp_diff);

	uint32_t* stack = l->stack;

	for(int i = 0; i < 16; i++)
	{
		if(0) LOG("[0x%02x] = 0x%08x, [0x%02x] = 0x%08x, [0x%02x] = 0x%08x, [0x%02x] = 0x%08x",
			i + 0, stack[i + 0], i + 1, stack[i + 1], i + 2, stack[i + 2], i + 3, stack[i + 3]);
		i += 3;
	}
	
	uint32_t* r = l->r;
	
	for(int i = 0; i < 4; i++)
	{
		if(0) LOG("r[%02x] = 0x%08x", i, r[i]);
	}
}

const uint32_t _stm_sp = (0xe << 28) | _BV(27) | _BV(21) | (rSP << 16);
const uint32_t _ldm_sp = _stm_sp | _BV(20);

const uint32_t _ldstm_reglist = _BV(1) | _BV(2) | _BV(3) | _BV(4);

const uint32_t _ldstm_da = 0;

static void csx_test_arm_ldmda(csx_test_p t)
{
	csx_core_p core = t->csx->core;

	ldstm_t ldstm;

	csx_test_arm_ldstm_setup_stack(t, &ldstm, 4);

	asm(
		"ldmda %[stack]!, {r1, r2, r3, r4}\n\t"
		"mov %[r1], r1\n\t"
		"mov %[r2], r2\n\t"
		"mov %[r3], r3\n\t"
		"mov %[r4], r4\n\t"
		: [stack] "+r" (ldstm.asp[1])
			, [r1] "=r" (ldstm.r[0])
			, [r2] "=r" (ldstm.r[1])
			, [r3] "=r" (ldstm.r[2])
			, [r4] "=r" (ldstm.r[3]) ::
		"r1", "r2", "r3", "r4"
		);

	csx_test_arm_ldm_dump_stack(t, &ldstm);

	/* **** */
	
	t->start_pc = t->pc = 0x10000000;
	SP = ldstm.esp[0];
	
	_cxx(t, _ldm_sp | _ldstm_da | _ldstm_reglist, sizeof(uint32_t));
	
	t->start_pc = t->pc = csx_test_run(t, 1);

	ldstm.esp[1] = SP;

	csx_test_arm_ldstm_assert_check(t, &ldstm, 1, 1);
}

const uint32_t _ldstm_db = _BV(24);

static void csx_test_arm_ldmdb(csx_test_p t)
{
	csx_core_p core = t->csx->core;

	ldstm_t ldstm;

	csx_test_arm_ldstm_setup_stack(t, &ldstm, 4);

	asm(
		"ldmdb %[stack]!, {r1, r2, r3, r4}\n\t"
		"mov %[r1], r1\n\t"
		"mov %[r2], r2\n\t"
		"mov %[r3], r3\n\t"
		"mov %[r4], r4\n\t"
		: [stack] "+r" (ldstm.asp[1])
			, [r1] "=r" (ldstm.r[0])
			, [r2] "=r" (ldstm.r[1])
			, [r3] "=r" (ldstm.r[2])
			, [r4] "=r" (ldstm.r[3]) ::
		"r1", "r2", "r3", "r4"
		);

	csx_test_arm_ldm_dump_stack(t, &ldstm);

	/* **** */
	
	t->start_pc = t->pc = 0x10000000;
	SP = ldstm.esp[0];
	
	_cxx(t, _ldm_sp | _ldstm_db | _ldstm_reglist, sizeof(uint32_t));
	
	t->start_pc = t->pc = csx_test_run(t, 1);

	ldstm.esp[1] = SP;

	csx_test_arm_ldstm_assert_check(t, &ldstm, 0, 1);
}

const uint32_t _ldstm_ia = _BV(23);

static void csx_test_arm_ldmia(csx_test_p t)
{
	csx_core_p core = t->csx->core;

	ldstm_t ldstm;

	csx_test_arm_ldstm_setup_stack(t, &ldstm, 4);

	asm(
		"ldmia %[stack]!, {r1, r2, r3, r4}\n\t"
		"mov %[r1], r1\n\t"
		"mov %[r2], r2\n\t"
		"mov %[r3], r3\n\t"
		"mov %[r4], r4\n\t"
		: [stack] "+r" (ldstm.asp[1])
			, [r1] "=r" (ldstm.r[0])
			, [r2] "=r" (ldstm.r[1])
			, [r3] "=r" (ldstm.r[2])
			, [r4] "=r" (ldstm.r[3]) ::
		"r1", "r2", "r3", "r4"
		);

	csx_test_arm_ldm_dump_stack(t, &ldstm);

	/* **** */
	
	t->start_pc = t->pc = 0x10000000;
	SP = ldstm.esp[0];
	
	_cxx(t, _ldm_sp | _ldstm_ia | _ldstm_reglist, sizeof(uint32_t));
	
	t->start_pc = t->pc = csx_test_run(t, 1);

	ldstm.esp[1] = SP;

	csx_test_arm_ldstm_assert_check(t, &ldstm, 4, 1);
}

const uint32_t _ldstm_ib = _BV(24) | _BV(23);

static void csx_test_arm_ldmib(csx_test_p t)
{
	csx_core_p core = t->csx->core;

	ldstm_t ldstm;

	csx_test_arm_ldstm_setup_stack(t, &ldstm, 4);

	asm(
		"ldmib %[stack]!, {r1, r2, r3, r4}\n\t"
		"mov %[r1], r1\n\t"
		"mov %[r2], r2\n\t"
		"mov %[r3], r3\n\t"
		"mov %[r4], r4\n\t"
		: [stack] "+r" (ldstm.asp[1])
			, [r1] "=r" (ldstm.r[0])
			, [r2] "=r" (ldstm.r[1])
			, [r3] "=r" (ldstm.r[2])
			, [r4] "=r" (ldstm.r[3]) ::
		"r1", "r2", "r3", "r4"
		);

	csx_test_arm_ldm_dump_stack(t, &ldstm);

	/* **** */

	t->start_pc = t->pc = 0x10000000;
	SP = ldstm.esp[0];
	
	_cxx(t, _ldm_sp | _ldstm_ib | _ldstm_reglist, sizeof(uint32_t));
	
	t->start_pc = t->pc = csx_test_run(t, 1);

	ldstm.esp[1] = SP;

	csx_test_arm_ldstm_assert_check(t, &ldstm, 5, 1);
}


static void csx_test_arm_ldstm(csx_test_p t)
{
	csx_test_arm_ldmda(t);
	csx_test_arm_ldmdb(t);
	csx_test_arm_ldmia(t);
	csx_test_arm_ldmib(t);
}	

	
static void csx_test_arm_mov(csx_test_p t)
{
	csx_core_p core = t->csx->core;
	
	t->start_pc = pc(t);

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(0, 0));
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000000 == csx_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(64, 0));
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000040 == csx_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(64, 26));
	t->start_pc = t->pc = csx_test_run(t, 1);
//	assert(0x00001000 == csx_reg_get(core, 0));
	assert(0x10000000 == csx_reg_get(core, 0));
}

void csx_test_arm(csx_test_p t)
{
	t->pc = t->start_pc;

	csx_test_arm_add(t);
	csx_test_arm_b(t);
	csx_test_arm_ldstm(t);
	csx_test_arm_mov(t);
	
	csx_test_arm_fn(t);
}
