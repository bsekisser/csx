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
	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 1);
	
	thumb_add_sub_i3_rn_rd(t, _ADD, 1, 1, 0);
	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 1);
	assert(csx_reg_get(core, 0) > csx_reg_get(core, 1));
	assert(65 == csx_reg_get(core, 0));
	
	thumb_add_sub_i3_rn_rd(t, _SUB, 1, 1, 0);
	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 1);
	assert(csx_reg_get(core, 0) < csx_reg_get(core, 1));
	assert(63 == csx_reg_get(core, 0));
}


void csx_test_thumb_b(csx_test_p t)
{
	csx_p csx = t->csx;
	csx_core_p core = csx->core;

	t->start_pc = t->pc = 0x100002b8;
	
//	_cxx(t, 0xf013, sizeof(uint16_t));
//	_cxx(t, 0xfccc, sizeof(uint16_t));
	_cxx(t, 0xfcccf013, sizeof(uint32_t));
//	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 1);

	uint32_t lr = csx_reg_get(core, rLR);
//	uint32_t hlr = lr & ~_BVM(11);
//	LOG("rLR = 0x%08x (0x%08x), rPC = 0x%08x", lr, hlr, pc(t));

//	assert(0x100132bc == lr);
//	assert(0x100002ba == pc(t));

	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 2);

//	pc_v = csx_reg_get(core, TEST_PC);
	lr = csx_reg_get(core, rLR);
//	LOG("rLR = 0x%08x, rPC = 0x%08x", lr, pc(t));

	assert(0x100002bd == lr);
	assert(0x10013c54 == pc(t));
	
	t->start_pc = t->pc = 0x10013c58 - 2;
	
	thumb_mov_rd_i(t, 0, 0);
	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 1);
	
	_cxx(t, 0xd00d, sizeof(uint16_t));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 1);

//	LOG("rLR = 0x%08x, rPC = 0x%08x", lr, pc(t));

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
	csx_mmu_p mmu = csx->mmu;

	uint32_t test_ldmia_addr = 0x10001000;

	uint32_t ea = test_ldmia_addr;
	for(int i = 0; i < 4; i++)
	{
		uint32_t test_value = _test_value(4 + i);
		csx_mmu_write(mmu, ea, test_value, sizeof(uint32_t));
		ea += 4;
	}

	csx_reg_set(core, 0, test_ldmia_addr);
	thumb_ldmia_rd_reglist(t, 0, 0xf0);

	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 1);

	for(int i = 4; i <= 7; i++)
	{
		uint32_t test_value = _test_value(i);
		uint32_t rxx_v = csx_reg_get(core, i);
		
		LOG("(test_value = 0x%08x) ?==? (r(%u) = 0x%08x)",
			test_value, i, rxx_v);
		
		assert(test_value == rxx_v);
	}

	uint32_t test_ldmia_addr_end = csx_reg_get(core, 0);
	LOG("r(0) == 0x%08x -- 0x%08x", test_ldmia_addr, test_ldmia_addr_end);
	
	uint32_t test_ldmia_addr_expect = test_ldmia_addr + (4 << 2);
	assert(test_ldmia_addr_end == test_ldmia_addr_expect);
	
	/* stmia */
	
	uint32_t test_stmia_addr = test_ldmia_addr + 0x1000;
	
	csx_reg_set(core, 0, test_stmia_addr);
	thumb_stmia_rd_reglist(t, 0, 0xf0);

	t->start_pc = t->pc = csx_test_run(t, t->start_pc | 1, pc(t), 1);
	
	ea = test_stmia_addr;
	for(int i = 4; i <= 7; i++)
	{
		uint32_t test_value = _test_value(i);
		uint32_t rxx_v = csx_mmu_read(mmu, ea, sizeof(uint32_t));
		
		LOG("(test_value = 0x%08x) ?==? (ea(%u) = 0x%08x)",
			test_value, i, rxx_v);
		
		assert(test_value == rxx_v);

		ea += 4;
	}

	uint32_t test_stmia_addr_end = csx_reg_get(core, 0);
	LOG("r(0) == 0x%08x -- 0x%08x", test_stmia_addr, test_stmia_addr_end);
	
	uint32_t test_stmia_addr_expect = test_stmia_addr + (4 << 2);
	assert(test_stmia_addr_end == test_stmia_addr_expect);
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
