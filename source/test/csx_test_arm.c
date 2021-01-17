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

static void csx_test_arm_add(csx_test_p t)
{
	csx_core_p core = t->csx->core;
	t->start_pc = t->pc = 0x10000000;

	uint32_t psr;

	/* result : inputs : clobbers */

	asm(
		"mov r1, #-1\n\t"
		"mov r2, #1\n\t"
		"adds r3, r1, r2\n\t"
		"mrs %[result], CPSR\n\t"
		: [result] "=r" (psr) :: "r1", "r2", "r3"
		);

	if(1) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u     /* expected */",
		!!(psr & CSX_PSR_N), !!(psr & CSX_PSR_Z),
		!!(psr & CSX_PSR_C), !!(psr & CSX_PSR_V));

	csx_reg_set(core, 1, -1);
	csx_reg_set(core, 2, 1);
	arm_adds_rn_rd_sop(t, 1, 0, arm_dpi_lsl_r_s(2, 0));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 3);

	csx_reg_set(core, 0, 12);
	csx_reg_set(core, 1, 1);
	arm_adds_rn_rd_sop(t, 0, 2, arm_dpi_lsl_r_s(1, 0));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 3);
	
	assert(12 == csx_reg_get(core, 0));
	assert(1 == csx_reg_get(core, 1));
	assert(13 == csx_reg_get(core, 2));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_N));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_Z));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_C));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_V));
	
	arm_subs_rn_rd_sop(t, 2, 3, arm_dpi_lsl_r_s(0, 0));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);

	assert(12 == csx_reg_get(core, 0));
	assert(1 == csx_reg_get(core, 1));
	assert(13 == csx_reg_get(core, 2));
	assert(1 == csx_reg_get(core, 3));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_N));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_Z));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_C));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_V));

	asm(
		"mov r1, #12\n\t"
		"mov r2, #13\n\t"
		"subs r3, r1, r2\n\t"
		"mrs %[result], CPSR\n\t"
		: [result] "=r" (psr) :: "r1", "r2", "r3"
		);

	if(1) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u     /* expected */",
		!!(psr & CSX_PSR_N), !!(psr & CSX_PSR_Z),
		!!(psr & CSX_PSR_C), !!(psr & CSX_PSR_V));

	arm_subs_rn_rd_sop(t, 0, 4, arm_dpi_lsl_r_s(2, 0));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 2);

	assert(-1 == csx_reg_get(core, 4));
	assert(1 == BEXT(CPSR, CSX_PSR_BIT_N));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_Z));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_C));
	assert(0 == BEXT(CPSR, CSX_PSR_BIT_V));
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

static inline uint32_t _test_value(uint8_t i)
{
		uint32_t test_value = i | i << 16;

		test_value |= test_value << 4;
		test_value |= test_value << 8;

		return(test_value);
}

static void csx_test_arm_ldstm(csx_test_p t)
{
	csx_core_p core = t->csx->core;
	
	t->start_pc = t->pc = 0x10005714;
	
	csx_reg_set(core, 4, _test_value(4));
	csx_reg_set(core, 14, _test_value(14));
	csx_reg_set(core, rSP, 0x10007500);
	
	_cxx(t, 0xe92d4010, sizeof(uint32_t));
	
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
	
	t->start_pc = t->pc = 0x10005724;
//	csx_reg_set(core, rSP, 0x10007500);
	
	_cxx(t, 0xe8bd4010, sizeof(uint32_t));
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
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

	csx_test_arm_add(t);
	csx_test_arm_b(t);
	csx_test_arm_ldstm(t);
	csx_test_arm_mov(t);
}
