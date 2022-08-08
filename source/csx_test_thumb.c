#include "csx.h"
#include "csx_core.h"

#include "csx_test.h"
#include "csx_test_utility.h"

#include "csx_test_thumb.h"
#include "csx_test_thumb_inst.h"

enum {
	_ADD = 0,
	_SUB,
};

void csx_test_thumb_add_sub_i3_rn_rd(csx_test_p t)
{
	csx_p csx = t->csx;
	csx_core_p core = csx->core;
	
	t->start_pc = t->pc = 0x10000000;
	
	thumb_mov_rd_i(t, 1, 64);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);
	
	thumb_add_sub_i3_rn_rd(t, _ADD, 1, 1, 0);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);
	assert(csx_reg_get(core, 0) > csx_reg_get(core, 1));
	assert(65 == csx_reg_get(core, 0));
	
	thumb_add_sub_i3_rn_rd(t, _SUB, 1, 1, 0);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);
	assert(csx_reg_get(core, 0) < csx_reg_get(core, 1));
	assert(63 == csx_reg_get(core, 0));
}

void csx_test_thumb_b(csx_test_p t)
{
	csx_p csx = t->csx;
	csx_core_p core = csx->core;

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

static inline uint32_t _test_value(uint8_t i)
{
		uint32_t test_value = i | i << 16;

		test_value |= test_value << 4;
		test_value |= test_value << 8;

		return(test_value);
}

void csx_test_thumb_ldstm(csx_test_p t)
{
	csx_p csx = t->csx;
	csx_core_p core = csx->core;

	t->start_pc = t->pc = 0x10000000;
	
	csx_reg_set(core, 0, 0x10001004);

	for(int i = 0; i < 8; i++)
		csx_mmu_write(t->csx->mmu, 0x10001000 + (i << 2), _test_value(i), sizeof(uint32_t));

	thumb_ldmia_rd_reglist(t, 0, 0xcc);
	t->start_pc = t->pc = csx_test_run_thumb(t, 1);

	for(int i = 0; i < 8; i++)
		LOG("r[%02u] = 0x%08x", i, csx_reg_get(core, i));
		
	assert(0x10001014 == csx_reg_get(core, 0));
	assert(_test_value(1) == csx_reg_get(core, 2));
	assert(_test_value(2) == csx_reg_get(core, 3));
	assert(_test_value(3) == csx_reg_get(core, 6));
	assert(_test_value(4) == csx_reg_get(core, 7));
}

void csx_test_pop_push(csx_test_p t)
{

}

void csx_test_thumb(csx_test_p t)
{
	t->pc = t->start_pc;

	csx_test_thumb_add_sub_i3_rn_rd(t);
	csx_test_thumb_b(t);
	csx_test_thumb_ldstm(t);
	csx_test_pop_push(t);
}
