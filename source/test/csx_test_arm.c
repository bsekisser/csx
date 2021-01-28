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

static void _csx_test_arm_add(csx_test_p t, int i)
{
	/* result : inputs : clobbers */

	uint32_t psr;

	switch(i)
	{
		case 1:
			asm(
				"mov r1, #-1\n\t"
				"mov r2, #1\n\t"
				"adds r3, r1, r2\n\t"
				"mrs %[result], CPSR\n\t"
				: [result] "=r" (psr) :: "r1", "r2", "r3"
				);
			break;
		case 2:
			asm(
				"mov r1, #12\n\t"
				"mov r2, #13\n\t"
				"subs r3, r1, r2\n\t"
				"mrs %[result], CPSR\n\t"
				: [result] "=r" (psr) :: "r1", "r2", "r3"
				);
			break;
	}

	if(1) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u     /* expected */",
		!!(psr & CSX_PSR_N), !!(psr & CSX_PSR_Z),
		!!(psr & CSX_PSR_C), !!(psr & CSX_PSR_V));
}

static void csx_test_arm_add(csx_test_p t)
{
	csx_core_p core = t->csx->core;
	t->start_pc = t->pc = 0x10000000;

	_csx_test_arm_add(t, 1);

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

	_csx_test_arm_add(t, 2);

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

	assert(new_pc == csx_reg_get(core, rTEST(rPC)));

	offset = eao(t, -3);
	new_pc = epc(t) + offset;
	
	if(0) LOG("pc = 0x%08x, start_pc = 0x%08x, offset == 0x%08x, new_pc = 0x%08x",
		pc(t), t->start_pc, offset, new_pc);

	arm_bl(t, offset);
	uint32_t expect_lr = pc(t);

	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
	assert(new_pc == csx_reg_get(core, rTEST(rPC)));
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

static void _csx_test_arm_ldstm(csx_test_p t, int i, int32_t* ddiff_in)
{
	static uint32_t stack[64];

	int32_t diff_in = (ddiff_in ? *ddiff_in : 0);
	uint32_t* sp_in = &stack[32] + diff_in;

	uint32_t* sp_v = sp_in;

	uint32_t evsp_in = 0x1007500 + diff_in;
	LOG("sp_in = 0x%08x, diff = 0x%08x, vsp_in = 0x%08x", (uint32_t)sp_v, diff_in, evsp_in);

	switch(i)
	{
		case 1:
			asm(
				"mov r1, #0x11\n\t"
				"mov r2, #0x22\n\t"
				"mov r3, #0x33\n\t"
				"mov r4, #0x44\n\t"
				"stmdb %[stack]!, {r1, r2, r3, r4}\n\t"
				: [stack] "+r" (sp_v) ::
				"r1", "r2", "r3", "r4"
			);
			break;
		case 2:
			asm(
				"mov r1, #0x11\n\t"
				"mov r2, #0x22\n\t"
				"mov r3, #0x33\n\t"
				"mov r4, #0x44\n\t"
				"ldmia %[stack]!, {r1, r2, r3, r4}\n\t"
				: [stack] "+r" (sp_v) ::
				"r1", "r2", "r3", "r4"
			);
			break;
		case 3:
			asm(
				"mov r1, #0x11\n\t"
				"mov r2, #0x22\n\t"
				"mov r3, #0x33\n\t"
				"mov r4, #0x44\n\t"
				"stmda %[stack]!, {r1, r2, r3, r4}\n\t"
				: [stack] "+r" (sp_v) ::
				"r1", "r2", "r3", "r4"
			);
			break;
		case 4:
			asm(
				"mov r1, #0x11\n\t"
				"mov r2, #0x22\n\t"
				"mov r3, #0x33\n\t"
				"mov r4, #0x44\n\t"
				"ldmib %[stack]!, {r1, r2, r3, r4}\n\t"
				: [stack] "+r" (sp_v) ::
				"r1", "r2", "r3", "r4"
			);
			break;
	}

	uint32_t* sp_out = (uint32_t*)sp_v;

	int32_t ddiff = sp_out - sp_in;

	uint32_t evsp_out = 0x1007500 + ddiff;
	LOG("sp_out = 0x%08x, diff = 0x%08x, vsp_out = 0x%08x", (uint32_t)sp_out, ddiff, evsp_out);

	uint32_t* start_address = MIN(sp_in, sp_out);
	uint32_t* end_address = MAX(sp_in, sp_out);

	uint32_t* ea = start_address;
	for(;ea < end_address; ea = &ea[1])
	{
		uint32_t eva = 0x10007500 + ((ea - MAX(sp_in, sp_out)) << 2);
		LOG("ea(0x%08x, 0x%08x) = 0x%08x", (uint32_t)ea, eva, *ea);
	}
	
	if(!ddiff_in)
		_csx_test_arm_ldstm(t, ++i, &ddiff);
}

static void csx_test_arm_ldstm(csx_test_p t)
{
	csx_core_p core = t->csx->core;
	
	_csx_test_arm_ldstm(t, 1, 0);

	t->start_pc = t->pc = 0x10005714;
	
	uint32_t reglist = _BV(1) | _BV(2) | _BV(3) | _BV(4);

	csx_reg_set(core, 1, _test_value(1));
	csx_reg_set(core, 2, _test_value(2));
	csx_reg_set(core, 3, _test_value(3));
	csx_reg_set(core, 4, _test_value(4));
	csx_reg_set(core, rSP, 0x10007500);

	_cxx(t, 0xe92d0000 | reglist, sizeof(uint32_t)); /* stmdb */
	
	t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
	
	csx_reg_set(core, 1, 0);
	csx_reg_set(core, 2, 0);
	csx_reg_set(core, 3, 0);
	csx_reg_set(core, 4, 0);
	
	t->start_pc = t->pc = 0x10005724;
//	csx_reg_set(core, rSP, 0x10007500);
	
	_cxx(t, 0xe8bd0000 | reglist, sizeof(uint32_t)); /* ldmia */
	if(1)
	{
		t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
		
		assert(_test_value(1) == csx_reg_get(core, 1));
		assert(_test_value(2) == csx_reg_get(core, 2));
		assert(_test_value(3) == csx_reg_get(core, 3));
		assert(_test_value(4) == csx_reg_get(core, 4));
	}

	if(0)
	{
		_csx_test_arm_ldstm(t, 3, 0);

		csx_reg_set(core, 1, _test_value(1));
		csx_reg_set(core, 2, _test_value(2));
		csx_reg_set(core, 3, _test_value(3));
		csx_reg_set(core, 4, _test_value(4));
		csx_reg_set(core, rSP, 0x10007500);

	//	uint32_t reglist = _BV(1) | _BV(2) | _BV(3) | _BV(4);
		_cxx(t, 0xe92d0000 | reglist, sizeof(uint32_t)); /* stmda */
		
		t->start_pc = t->pc = csx_test_run(t, t->start_pc, pc(t), 1);
	}
}	

	
static void csx_test_arm_mov(csx_test_p t)
{
	csx_core_p core = t->csx->core;
	
	t->start_pc = pc(t);

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
