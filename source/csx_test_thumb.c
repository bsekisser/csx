#include "csx_test_thumb.h"
#include "csx_test_thumb_asm.h"
#include "csx_test_thumb_inst.h"

#include "csx_test_utility.h"
#include "soc.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

enum {
	_ADD = 0,
	_SUB,
};

typedef uint32_t (*thumb_fn)(uint32_t* rd, const uint32_t rn, const uint32_t rm);

uint32_t _test_thumb_asm(csx_test_p t, thumb_fn fn, uint32_t rn, uint32_t rm, uint32_t* xpsr) {
	volatile uint32_t xres = fn(0, rn, rm);

	asm volatile ("mrs %[xpsr], CPSR\n\t"
		: [xpsr] "=r" (*xpsr)
		: "r" (xres)
		: "cc");

	return(xres);

	UNUSED(t);
}

uint32_t _test_thumb_adds_rn_i_inst(csx_test_p t, uint32_t rn, uint32_t rm, uint32_t* cpsr) {
	soc_core_p core = t->csx->core;

	soc_core_reg_set(core, 1, rn);

	thumb_add_sub_i3_rn_rd(t, _ADD, rm, 1, 0);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);

	*cpsr = CPSR;
	return(soc_core_reg_get(core, 0));
}

void csx_test_thumb_adds_rn_i(csx_test_p t, uint32_t rn, uint rm) {
	
	uint32_t xpsr = 0, xres = 0;
	uint32_t cpsr = 0, cres = 0;
	
	thumb_fn fn = 0;
	
	switch (rm) {
		case 1:
			fn = _test_thumb_adds_rn_1_asm;
			break;
		case 7:
			fn = _test_thumb_adds_rn_7_asm;
			break;
		default:
			LOG_ACTION(exit(-1));
			break;
	}
	
	xres = _test_thumb_asm(t, fn, rn, rm, &xpsr);
	cres = _test_thumb_adds_rn_i_inst(t, rn, rm, &cpsr);

//	TRACE_PSR(xpsr);
//	TRACE_PSR(cpsr);
	
	assert(cres == xres);
	_assert_cpsr_xpsr(t, cpsr, xpsr);
}

#define csx_test_thumb_adds_rn_1(_t, _rn) \
	csx_test_thumb_adds_rn_i(_t, (_rn), 1)

#define csx_test_thumb_adds_rn_7(_t, _rn) \
	csx_test_thumb_adds_rn_i(_t, (_rn), 7)

void csx_test_thumb_add_sub_i3_rn_rd(csx_test_p t)
{
	csx_p csx = t->csx;
	soc_core_p core = csx->core;
	
	t->start_pc = t->pc = 0x10000000;
	
	thumb_mov_rd_i(t, 1, 64);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);
	
	thumb_add_sub_i3_rn_rd(t, _ADD, 1, 1, 0);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);
	assert(soc_core_reg_get(core, 0) > soc_core_reg_get(core, 1));
	assert(65 == soc_core_reg_get(core, 0));
	
	thumb_add_sub_i3_rn_rd(t, _SUB, 1, 1, 0);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);
	assert(soc_core_reg_get(core, 0) < soc_core_reg_get(core, 1));
	assert(63 == soc_core_reg_get(core, 0));

	csx_test_thumb_adds_rn_1(t, 0);
	csx_test_thumb_adds_rn_1(t, 1);
	csx_test_thumb_adds_rn_1(t, ~0);
	csx_test_thumb_adds_rn_1(t, ~0 - 1);
	csx_test_thumb_adds_rn_1(t, ~0UL >> 1);
	csx_test_thumb_adds_rn_1(t, (~0UL >> 1) - 1);

	csx_test_thumb_adds_rn_7(t, 0);
	csx_test_thumb_adds_rn_7(t, 1);
	csx_test_thumb_adds_rn_7(t, ~0);
	csx_test_thumb_adds_rn_7(t, ~0 - 1);
	csx_test_thumb_adds_rn_7(t, ~0UL >> 1);
	csx_test_thumb_adds_rn_7(t, (~0UL >> 1) - 1);
}

void csx_test_thumb_b(csx_test_p t)
{
	csx_p csx = t->csx;
	soc_core_p core = csx->core;

	if(1) {
		t->start_pc = t->pc = 0x100002b8;
	
		_cxx(t, 0xf013, sizeof(uint16_t)); /* theoretical test */
		t->start_pc = t->pc = csx_test_run_thumb(t, 1);

		if(0) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);

		assert(0x100132bc == LR);
		assert(0x100002ba == pc(t));

		_cxx(t, 0xfccc, sizeof(uint16_t)); /* theoretical test */
		t->start_pc = t->pc = csx_test_run_thumb(t, 1);

		if(0) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);

		assert(0x100002bd == LR);
		assert(0x10013c54 == pc(t));
	}

	t->start_pc = t->pc = 0x100002b8;

	_cxx(t, 0xfcccf013, sizeof(uint32_t));
	t->start_pc = t->pc = csx_test_run_thumb(t, 2);

	if(0) LOG("LR = 0x%08x, PC = 0x%08x", LR, PC);

	assert(0x100002bd == LR);
	assert(0x10013c54 == pc(t));
	
	t->start_pc = t->pc = 0x10013c58 - 2;
	
	thumb_mov_rd_i(t, 0, 0);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);
	
	_cxx(t, 0xd00d, sizeof(uint16_t));
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);

	if(0) LOG("rLR = 0x%08x, rPC = 0x%08x", LR, pc(t));

	assert(0x10013c76 == pc(t));
}

void csx_test_thumb_ldstm(csx_test_p t)
{
	csx_p csx = t->csx;
	soc_core_p core = csx->core;

	t->start_pc = t->pc = 0x10000000;
	
	soc_core_reg_set(core, 0, 0x10001004);

	for(int i = 0; i < 8; i++)
		csx_soc_write(csx, 0x10001000 + (i << 2), _test_value(i), sizeof(uint32_t));

	thumb_ldmia_rd_reglist(t, 0, 0xcc);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);

//	for(int i = 0; i < 8; i++)
//		LOG("r[%02u] = 0x%08x", i, soc_core_reg_get(core, i));
		
	assert(0x10001014 == soc_core_reg_get(core, 0));
	assert(_test_value(1) == soc_core_reg_get(core, 2));
	assert(_test_value(2) == soc_core_reg_get(core, 3));
	assert(_test_value(3) == soc_core_reg_get(core, 6));
	assert(_test_value(4) == soc_core_reg_get(core, 7));
}

void csx_test_pop_push(csx_test_p t)
{
	UNUSED(t);
}

void csx_test_thumb(csx_test_p t)
{
	t->pc = t->start_pc;

	csx_test_thumb_add_sub_i3_rn_rd(t);
	csx_test_thumb_b(t);
	csx_test_thumb_ldstm(t);
	csx_test_pop_push(t);
}
