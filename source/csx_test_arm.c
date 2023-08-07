#include "csx_test_arm.h"
#include "csx_test_arm_asm.h"
#include "csx_test_arm_inst.h"

/* **** */

#include "soc_core_psr.h"
#include "soc_core_test.h"
#include "soc_core.h"

#include "csx_soc.h"
#include "csx_test.h"
#include "csx_test_utility.h"
#include "csx.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

#include <stdint.h>
#include <string.h>

/* **** */

typedef uint32_t (*csx_test_set_fn)(csx_test_p t, uint32_t* psr, unsigned j, unsigned k);

static int _csx_test_set(csx_test_p t,
	csx_test_set_fn asm_fn,
	csx_test_set_fn inst_fn,
	unsigned jk_limit,
	uint32_t psr_mask)
{
	uint32_t xres = 0, tres = 0;
	uint32_t xpsr = 0, tpsr = 0;

	unsigned j = 0, k = 0;
	for(j = 0; j < jk_limit; j++) {
		unsigned jj = (jk_limit > 15) ? (j << 24) : _test_value(j);
		for(k = 0; k < jk_limit; k++) {
			unsigned kk = (jk_limit > 15) ? (k << 24) : _test_value(k);

			xres = asm_fn(t, &xpsr, jj, kk);
			tres = inst_fn(t, &tpsr, jj, kk);

			if(xres != tres)
				goto _csx_test_set_fail;

			if(0 != psr_mask) {
				if(!_test_cpsr_xpsr_mask(t, tpsr, xpsr, psr_mask))
					goto _csx_test_set_fail;
			} else {
				if(!_test_cpsr_xpsr(t, tpsr, xpsr))
						goto _csx_test_set_fail;
			}

		}
	}

	return(1);

_csx_test_set_fail:
	TRACE_PSR(xpsr);
	TRACE_PSR(tpsr);
	LOG("j = 0x%03x, k = 0x%03x, xres = 0x%08x, tres = 0x%08x\n",
		j, k, xres, tres);

	return(0);
}

/* **** */

static inline uint32_t epc(csx_test_p t)
{
	return(pc(t) + 8);
}

static inline uint32_t eao(csx_test_p t, int32_t ieao)
{
	/* (((offset - 8) >> 2) & 0x00ffffff) */

	if(0 > ieao)
		ieao--;

	const uint32_t ea = (ieao << 2) - 4;

	if(0) LOG("ea = 0x%08x", ea);

	return(ea);

	UNUSED(t);
}

/* **** */

static uint32_t csx_test_arm_adcs_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 1, ir0);
	soc_core_reg_set(core, 2, ir1);

	t->start_pc = t->pc = 0x10000000;
	arm_adds_rn_rd_sop(t, 1, 0, arm_dpi_lsl_r_s(2, 0));
	arm_adcs_rn_rd_sop(t, 1, 0, arm_dpi_lsl_r_s(2, 0));
	t->start_pc = t->pc = csx_test_run(t, 2);

	*psr = CPSR;

	res = soc_core_reg_get(core, 0);

	return(res);
}

static unsigned _test_xres_res(csx_test_p t, unsigned xres, unsigned res)
{
	const unsigned result = (xres == res);
	
	if(0 == result) {
		LOG("xres = 0x%08x, res = 0x%08x", xres, res);
	}

	return(result);
	UNUSED(t);
}

static void csx_test_arm_adcs(csx_test_p t)
{
	t->start_pc = t->pc = 0x10000000;

	int savedTrace = _soc_core_test_trace(t->core, 0, 0);

	uint32_t res = 0, xres = 0;
	uint32_t xpsr = 0, cpsr = 0;

	xres = csx_test_arm_adcs_asm(t, &xpsr, ~0, 1);
	res = csx_test_arm_adcs_inst(t, &cpsr, ~0, 1);

	assert(_test_xres_res(t, xres, res));
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	assert(_test_nzcv(t, 0, 0, 1, 0));

	xres = csx_test_arm_adcs_asm(t, &xpsr, 12, 1);
	res = csx_test_arm_adcs_inst(t, &cpsr, 12, 1);

	assert(xres == res);
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	assert(_test_nzcv(t, 0, 0, 0, 0));

	assert(_csx_test_set(t,
		csx_test_arm_adcs_asm, csx_test_arm_adcs_inst,
			256, 0));

	_soc_core_test_trace(t->core, 0, &savedTrace);
}

/* **** */

static uint32_t csx_test_arm_adds_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);

	t->start_pc = t->pc = 0x10000000;
	arm_adds_rn_rd_sop(t, 0, 0, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 1);

	*psr = CPSR;

	res = soc_core_reg_get(core, 0);

	return(res);
}

static void csx_test_arm_adds(csx_test_p t)
{
	t->start_pc = t->pc = 0x10000000;

	uint32_t res = 0, xres = 0;
	uint32_t xpsr = 0, cpsr = 0;

	xres = csx_test_arm_adds_asm(t, &xpsr, ~0, 1);
	res = csx_test_arm_adds_inst(t, &cpsr, ~0, 1);

	assert(xres == res);
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	assert(_test_nzcv(t, 0, 1, 1, 0));

	xres = csx_test_arm_adds_asm(t, &xpsr, 12, 1);
	res = csx_test_arm_adds_inst(t, &cpsr, 12, 1);

	assert(xres == res);
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	assert(_test_nzcv(t, 0, 0, 0, 0));

	assert(_csx_test_set(t,
		csx_test_arm_adds_asm, csx_test_arm_adds_inst,
			256, 0));
}

/* **** */

static uint32_t csx_test_arm_ands_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);

	t->start_pc = t->pc = 0x10000000;
	arm_adds_rn_rd_sop(t, 0, 2, arm_dpi_lsl_r_s(1, 0)); /* << ensure predictable psr result */
	arm_ands_rn_rd_sop(t, 0, 2, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 2);

	*psr = CPSR;

	res = soc_core_reg_get(core, 2);

	return(res);
}

static void csx_test_arm_ands(csx_test_p t)
{
	t->start_pc = t->pc = 0x10000000;

	assert(_csx_test_set(t,
		csx_test_arm_ands_asm, csx_test_arm_ands_inst,
			16, 0));
}

/* **** */

static void csx_test_arm_b(csx_test_p t)
{
	const soc_core_p core = t->core;

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

	t->start_pc = t->pc = csx_test_run(t, 1) & ~3U;
	assert(new_pc == PC);
	assert(expect_lr == LR);
	assert(CPSR & SOC_CORE_PSR_BIT_T);

	if(0) LOG("start_pc = 0x%08x, pc(t) = 0x%08x, LR = 0x%08x", t->start_pc, pc(t), LR);

	offset = eao(t, 2) | 2;
	new_pc = epc(t) + offset;

	arm_blx(t, offset);
	expect_lr = pc(t);

	t->start_pc = t->pc = csx_test_run(t, 1) & ~3U;
	assert(new_pc == PC);
	assert(expect_lr == LR);
	assert(CPSR & SOC_CORE_PSR_BIT_T);

	if(0) LOG("start_pc = 0x%08x, pc(t) = 0x%08x, LR = 0x%08x", t->start_pc, pc(t), LR);
}

/* **** */

static uint32_t csx_test_arm_bics_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);

	t->start_pc = t->pc = 0x10000000;
	arm_adds_rn_rd_sop(t, 0, 2, arm_dpi_lsl_r_s(1, 0)); /* << ensure predictable psr result */
	arm_bics_rn_rd_sop(t, 0, 2, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 2);

	*psr = CPSR;

	res = soc_core_reg_get(core, 2);

	return(res);
}

static void csx_test_arm_bics(csx_test_p t)
{
	t->start_pc = t->pc = 0x10000000;

//	uint32_t res = 0, xres = 0;
//	uint32_t xpsr = 0, cpsr = 0;

	assert(_csx_test_set(t,
		csx_test_arm_bics_asm, csx_test_arm_bics_inst,
			16, 0));
}

/* **** */

static uint32_t csx_test_arm_cmp_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	const uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);

	t->start_pc = t->pc = 0x10000000;
	arm_cmps_rn_rd_sop(t, 0, 0, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 1);

	*psr = CPSR;

	return(res);
}

static uint32_t csx_test_arm_subs_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);

static void csx_test_arm_cmp(csx_test_p t)
{
	int savedTrace = _soc_core_test_trace(t->core, 0, 0);
	
/* **** */

	uint32_t r[7];

	for(int i = 0; i < 7; i++)
		r[i] = 0;

	r[5] = 1;
	r[5] <<= 29;
	r[3] = r[5] + 0;
	r[4] = 0xe59ff000;
	r[0] = 0;
	r[3] += 0x64;

	r[6] = 0x1c;

/* **** */

	uint32_t xres = 0, res = 0;
	uint32_t xpsr = 0, cpsr = 0;

//	LOG("r0 = 0x%08x, r1 = 0x%08x, r2 = 0x%08x", r[0], r[1], r[2]);
//	LOG("r3 = 0x%08x, r4 = 0x%08x, r5 = 0x%08x", r[3], r[4], r[5]);

	for(int count = 9; count; count--)
	{
		r[1] = r[0] + r[5];
		r[2] = r[0] + r[3];
		r[2] = r[2] - r[1];
		r[2] -= 0x08;
		r[2] |= r[4];
		r[0] += 0x04;

//		LOG("r0 = 0x%08x, r1 = 0x%08x, r2 = 0x%08x", r[0], r[1], r[2]);
//		LOG("r3 = 0x%08x, r4 = 0x%08x, r5 = 0x%08x", r[3], r[4], r[5]);

		xres = csx_test_arm_cmp_asm(t, &xpsr, r[0], r[6]);
		res = csx_test_arm_cmp_inst(t, &cpsr, r[0], r[6]);

		assert(xres == res);
		assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	};

	_soc_core_test_trace(t->core, 0, &savedTrace);
}

/* **** */

static uint32_t csx_test_arm_eors_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);

	t->start_pc = t->pc = 0x10000000;
	arm_adds_rn_rd_sop(t, 0, 2, arm_dpi_lsl_r_s(1, 0)); /* << ensure predictable psr result */
	arm_eors_rn_rd_sop(t, 0, 2, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 2);

	*psr = CPSR;

	res = soc_core_reg_get(core, 2);

	return(res);
}

static void csx_test_arm_eors(csx_test_p t)
{
	t->start_pc = t->pc = 0x10000000;

//	uint32_t res = 0, xres = 0;
//	uint32_t xpsr = 0, cpsr = 0;

	assert(_csx_test_set(t,
		csx_test_arm_eors_asm, csx_test_arm_eors_inst,
			16, 0));
}

/* **** */

static void csx_test_arm_dpi(csx_test_p t)
{
	const soc_core_p core = t->core;

	int savedTrace = _soc_core_test_trace(core, 0, 0);

	t->start_pc = t->pc = 0x10000000;

	arm_movs_rd_imm(t, 0, 0);
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000000 == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 0, 1, CF));

	arm_movs_rd_imm(t, 0, 0x80);
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000080 == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 0, 0, CF));

	arm_rors_rd_imm_is(t, 0, 0x80, 2);
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000020 == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 0, 0, 0));

	arm_rors_rd_imm_is(t, 1, 0x80, 8);
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x80000000 == soc_core_reg_get(core, 1));
	assert(_test_nzc(t, 1, 0, 1));

	arm_asrs_rd_rm_is(t, 0, 1, 0);
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0xffffffff == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 1, 0, 1));

	arm_rors_rd_imm_is(t, 1, 0x40, 8);
	arm_asrs_rd_rm_is(t, 0, 1, 0);
	t->start_pc = t->pc = csx_test_run(t, 2);
	assert(0x00000000 == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 0, 1, 0));

	arm_rors_rd_imm_is(t, 1, 0x80, 8);
	arm_asrs_rd_rm_is(t, 0, 1, 31);
	t->start_pc = t->pc = csx_test_run(t, 2);
	assert(0xffffffff == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 1, 0, 0));

	arm_rors_rd_imm_is(t, 1, 0x80, 8);
	arm_asrs_rd_rm_is(t, 0, 1, 0);
	t->start_pc = t->pc = csx_test_run(t, 2);
	assert(0xffffffff == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 1, 0, 1));

	arm_rors_rd_imm_is(t, 1, 0x80, 8);
	arm_asrs_rd_rm_is(t, 1, 1, 0);
	arm_lsls_rd_rm_is(t, 1, 1, 16);
	arm_lsrs_rd_rm_is(t, 1, 1, 8);
	t->start_pc = t->pc = csx_test_run(t, 4);
	assert(0x00ffff00 == soc_core_reg_get(core, 1));
	assert(_test_nzc(t, 0, 0, 0));

	arm_rors_rd_imm_is(t, 0, 1, 16);
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00010000 == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 0, 0, 0));

	arm_rors_rd_imm_is(t, 0, 1, 30);
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000004 == soc_core_reg_get(core, 0));
	assert(_test_nzc(t, 0, 0, 0));
	
	arm_mov_rd_imm(t, 0, 0x01);
	arm_add_rn_rd_sop(t, 0, 1, arm_dpi_lsl_r_s(0, 3));
	t->start_pc = t->pc = csx_test_run(t, 2);
	assert(0x00000009 == soc_core_reg_get(core, 1));
	assert(_test_nzc(t, 0, 0, 0));

	arm_mov_rd_imm(t, 0, 0x01);
	arm_rsb_rn_rd_sop(t, 0, 1, arm_dpi_lsl_r_s(0, 3));
	t->start_pc = t->pc = csx_test_run(t, 2);
	assert(0x00000007 == soc_core_reg_get(core, 1));
	assert(_test_nzc(t, 0, 0, 0));

	arm_mov_rd_imm(t, 0, 0x1f);
	arm_mov_rd_imm(t, 1, 0x09);
	arm_sub_rn_rd_sop(t, 1, 1, arm_dpi_lsr_r_s(0, 4));
	t->start_pc = t->pc = csx_test_run(t, 3);
	assert(0x00000008 == soc_core_reg_get(core, 1));

	arm_lsl_rd_rm_is(t, 0, 0, 0);
	t->start_pc = t->pc = csx_test_run(t, 1);

	_soc_core_test_trace(core, 0, &savedTrace);
}

/* **** */

typedef struct ldstm_t* ldstm_p;
typedef struct ldstm_t {
	uint32_t						stack[16];
	uint32_t						r[4];

	uint32_t*						asp[2];
	uint32_t						esp[2];
}ldstm_t;

static void csx_test_arm_ldstm_assert_check(csx_test_p t,
	ldstm_p l,
	unsigned tvs,
	unsigned rvs)
{
	const ptrdiff_t asp_diff = (uintptr_t)l->asp[1] - (uintptr_t)l->asp[0];
	const ptrdiff_t esp_diff = (uintptr_t)l->esp[1] - (uintptr_t)l->esp[0];

	if(0) LOG("asp_in = 0x%016" PRIxPTR ", asp_out 0x%016" PRIxPTR ", asp_diff = 0x%08" PRIxPTR,
		(uintptr_t)l->asp[0], (uintptr_t)l->asp[1], asp_diff);
	if(0) LOG("esp_in = 0x%016x, esp_out 0x%016x, esp_diff = 0x%08" PRIxPTR,
		(uintptr_t)l->esp[0], (uintptr_t)l->esp[1], esp_diff);

	assert(asp_diff == esp_diff);

	for(int i = 0; i < 16; i++)
	{
		const uint32_t espv = 0x10001000 + (i << 2);
		const uint32_t esiv = csx_read(t->csx, espv, sizeof(uint32_t));
		assert(l->stack[i] == esiv);
	}

	for(int i = 0; i < 4; i++) {
		const uint32_t rv = soc_core_reg_get(t->core, rvs + i);
		if(0) LOG("r[%02x] = 0x%08x", i, rv);

		assert(_test_value(tvs + i) == rv);
	}
}

static void csx_test_arm_ldstm_setup_stack(csx_test_p t, ldstm_p l, unsigned spat)
{
	l->esp[0] = 0x10001000 + (spat << 2);
	l->esp[1] = l->esp[0];

	for(int i = 0; i < 16; i++) {
		const uint32_t tvi = _test_value(i);

		l->stack[i] = tvi;

		csx_write(t->csx, 0x10001000 + (i << 2), sizeof(uint32_t), tvi);
	}

	l->asp[0] = &l->stack[spat];
	l->asp[1] = l->asp[0];
}

static void csx_test_arm_ldm_dump_stack(
	csx_test_p t,
	ldstm_p l)
{
	const ptrdiff_t sp_diff = l->asp[1] - l->asp[0];

	if(0) LOG("asp_in = 0x%08" PRIxPTR ", asp_out 0x%08" PRIxPTR ", asp_diff = 0x%08" PRIxPTR,
		(uintptr_t)l->asp[0], (uintptr_t)l->asp[1], sp_diff);

	const uint32_t* stack = l->stack;

	for(int i = 0; i < 16; i++)
	{
		if(0) LOG("[0x%02x] = 0x%08x, [0x%02x] = 0x%08x, [0x%02x] = 0x%08x, [0x%02x] = 0x%08x",
			i + 0, stack[i + 0], i + 1, stack[i + 1], i + 2, stack[i + 2], i + 3, stack[i + 3]);
		i += 3;
	}

	const uint32_t* r = l->r;

	for(int i = 0; i < 4; i++)
	{
		if(0) LOG("r[%02x] = 0x%08x", i, r[i]);
	}

	UNUSED(t);
}

enum {
	_stm_sp = (0xeUL << 28) | _BV(27) | _BV(21) | (rSP << 16),
	_ldm_sp = _stm_sp | _BV(20),
//
	_ldstm_reglist = _BV(1) | _BV(2) | _BV(3) | _BV(4),
//
	_ldstm_da = 0UL,
};

static void csx_test_arm_ldmda(csx_test_p t)
{
	const soc_core_p core = t->core;

	ldstm_t ldstm;

	csx_test_arm_ldstm_setup_stack(t, &ldstm, 4);

#if defined(__arm__) && !defined(__aarch64__)
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
#else
	assert(0); // TODO
#endif

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
	const soc_core_p core = t->core;

	ldstm_t ldstm;

	csx_test_arm_ldstm_setup_stack(t, &ldstm, 4);

#if defined(__arm__) && !defined(__aarch64__)
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
#else
	assert(0); // TODO
#endif

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
	const soc_core_p core = t->core;

	ldstm_t ldstm;

	csx_test_arm_ldstm_setup_stack(t, &ldstm, 4);

#if defined(__arm__) && !defined(__aarch64__)
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
#else
	assert(0); // TODO
#endif

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
	const soc_core_p core = t->core;

	ldstm_t ldstm;

	csx_test_arm_ldstm_setup_stack(t, &ldstm, 4);

#if defined(__arm__) && !defined(__aarch64__)
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
#else
	assert(0); // TODO
#endif

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

/* **** */

static void csx_test_arm_mov(csx_test_p t)
{
	const soc_core_p core = t->core;

	int savedTrace = _soc_core_test_trace(core, 0, 0);

	t->start_pc = pc(t);

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(0, 0));
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000000 == soc_core_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(64, 0));
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000040 == soc_core_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(64, 26));
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00001000 == soc_core_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(64, 28));
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x00000400 == soc_core_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(0x3f, (0xe << 1))); /* listed in arm manual */
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x000003f0 == soc_core_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(0xfc, (0xf << 1))); /* listed in arm manual */
	t->start_pc = t->pc = csx_test_run(t, 1);
	assert(0x000003f0 == soc_core_reg_get(core, 0));

	_soc_core_test_trace(core, 0, &savedTrace);
}

/* **** */

static uint32_t csx_test_arm_rsbs_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);

	t->start_pc = t->pc = 0x10000000;
	arm_rsbs_rn_rd_sop(t, 0, 0, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 1);

	*psr = CPSR;

	res = soc_core_reg_get(core, 0);

	return(res);
}

static void csx_test_arm_rsbs(csx_test_p t)
{
	t->start_pc = t->pc = 0x10000000;

	int savedTrace = _soc_core_test_trace(t->core, 0, 0);

	assert(_csx_test_set(t,
		csx_test_arm_rsbs_asm, csx_test_arm_rsbs_inst,
			256, 0));

	_soc_core_test_trace(t->core, 0, &savedTrace);
}

static uint32_t csx_test_arm_rscs_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);
	soc_core_reg_set(core, 2, 0);

	t->start_pc = t->pc = 0x10000000;
	arm_adds_rn_rd_sop(t, 2, 2, arm_dpi_lsl_r_s(2, 0));
	arm_rscs_rn_rd_sop(t, 0, 0, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 2);

	*psr = CPSR;

	res = soc_core_reg_get(core, 0);

	return(res);
}

static void csx_test_arm_rscs(csx_test_p t)
{
	t->start_pc = t->pc = 0x10000000;

	int savedTrace = _soc_core_test_trace(t->core, 0, 0);

	assert(_csx_test_set(t,
		csx_test_arm_rscs_asm, csx_test_arm_rscs_inst,
			256, 0));

	_soc_core_test_trace(t->core, 0, &savedTrace);
}

/* **** */

static uint32_t csx_test_arm_sbcs_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);
	soc_core_reg_set(core, 2, 0);

	t->start_pc = t->pc = 0x10000000;
	arm_adds_rn_rd_sop(t, 2, 2, arm_dpi_lsl_r_s(2, 0));
	arm_sbcs_rn_rd_sop(t, 0, 0, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 2);

	*psr = CPSR;

	res = soc_core_reg_get(core, 0);

	return(res);
}

static void csx_test_arm_sbcs(csx_test_p t)
{
	t->start_pc = t->pc = 0x10000000;

	int savedTrace = _soc_core_test_trace(t->core, 0, 0);

	assert(_csx_test_set(t,
		csx_test_arm_sbcs_asm, csx_test_arm_sbcs_inst,
			256, 0));

	_soc_core_test_trace(t->core, 0, &savedTrace);
}


/* **** */

static uint32_t csx_test_arm_subs_inst(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1)
{
	const soc_core_p core = t->core;
	uint32_t res = 0;

	soc_core_reg_set(core, 0, ir0);
	soc_core_reg_set(core, 1, ir1);

	t->start_pc = t->pc = 0x10000000;
	arm_subs_rn_rd_sop(t, 0, 0, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, 1);

	*psr = CPSR;

	res = soc_core_reg_get(core, 0);

	return(res);
}

static void csx_test_arm_subs(csx_test_p t)
{
	int savedTrace = _soc_core_test_trace(t->core, 0, 0);

	t->start_pc = t->pc = 0x10000000;

	uint32_t res = 0, xres = 0;
	uint32_t xpsr = 0, cpsr = 0;

	xres = csx_test_arm_subs_asm(t, &xpsr, 13, 12);
	res = csx_test_arm_subs_inst(t, &cpsr, 13, 12);

	assert(1 == res);
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	assert(_test_nzcv(t, 0, 0, 1, 0));

	xres = csx_test_arm_subs_asm(t, &xpsr, 12, 13);
	res = csx_test_arm_subs_inst(t, &cpsr, 12, 13);

//	LOG("xres == 0x%08x, res = 0x%08x", xres, res);
//	fflush(stdout); sync(); sync(); sync();

	assert(~0U == res);
	assert(res == xres);
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	assert(_test_nzcv(t, 1, 0, 0, 0));

	xres = csx_test_arm_subs_asm(t, &xpsr, 0x1c, 0x1c);
	res = csx_test_arm_subs_inst(t, &cpsr, 0x1c, 0x1c);

	assert(0 == res);
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	assert(_test_nzcv(t, 0, 1, 1, 0));

	xres = csx_test_arm_subs_asm(t, &xpsr, 0x1d, 0x1c);
	res = csx_test_arm_subs_inst(t, &cpsr, 0x1d, 0x1c);

	assert(1 == res);
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
	assert(_test_nzcv(t, 0, 0, 1, 0));

	assert(_csx_test_set(t,
		csx_test_arm_subs_asm, csx_test_arm_subs_inst,
			256, 0));

	_soc_core_test_trace(t->core, 0, &savedTrace);
}

/* **** */

void csx_test_arm(csx_test_p t)
{
	t->pc = t->start_pc;

	csx_test_arm_adcs(t);
	csx_test_arm_adds(t);
	csx_test_arm_ands(t);
	csx_test_arm_b(t);
	csx_test_arm_bics(t);
	csx_test_arm_cmp(t);
	csx_test_arm_eors(t);
	csx_test_arm_ldstm(t);
	csx_test_arm_mov(t);
	csx_test_arm_rsbs(t);
	csx_test_arm_rscs(t);
	csx_test_arm_sbcs(t);
	csx_test_arm_subs(t);

	/* **** */

	csx_test_arm_dpi(t);
}
