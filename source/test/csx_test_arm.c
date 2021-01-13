#include "csx.h"
#include "csx_core.h"
#include "csx_test.h"
#include "csx_test_utility.h"

#include "csx_test_arm_inst.h"

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

static void csx_test_arm_b(csx_test_p t)
{
	csx_core_p core = t->csx->core;

	uint32_t offset = eao(t, 3);
	uint32_t new_pc = epc(t) + offset;
	
	if(0) LOG("pc = 0x%08x, start_pc = 0x%08x, offset == 0x%08x, new_pc = 0x%08x",
		pc(t), t->start_pc, offset, new_pc);
	
	arm_b(t, offset);
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);

	if(0) LOG("pc = 0x%08x", pc(t));

	assert(new_pc == csx_reg_get(core, TEST_PC));

	offset = eao(t, -3);
	new_pc = epc(t) + offset;
	
	if(0) LOG("pc = 0x%08x, start_pc = 0x%08x, offset == 0x%08x, new_pc = 0x%08x",
		pc(t), t->start_pc, offset, new_pc);

	arm_bl(t, offset);
	uint32_t expect_lr = pc(t);

	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
	assert(new_pc == csx_reg_get(core, TEST_PC));
	assert(expect_lr == csx_reg_get(core, rLR));
	
	if(0) LOG("start_pc = 0x%08x, pc(t) = 0x%08x, LR = 0x%08x", t->start_pc, pc(t), csx_reg_get(core, rLR));
}

static void csx_test_arm_mov(csx_test_p t)
{
	csx_core_p core = t->csx->core;
	
	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(0, 0));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
	assert(0x00000000 == csx_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(64, 0));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
	assert(0x00000040 == csx_reg_get(core, 0));

	arm_mov_rd_sop(t, 0, arm_dpi_ror_i_s(64, 26));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
	assert(0x00001000 == csx_reg_get(core, 0));
}

void csx_test_arm(csx_test_p t)
{
	t->pc = t->start_pc;

	csx_test_arm_b(t);
	csx_test_arm_mov(t);
}
