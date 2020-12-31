#include "csx.h"
#include "csx_core.h"
#include "csx_test.h"

#include "csx_test_arm_inst.h"

static inline uint32_t pc(csx_test_p t)
{
	return(t->pc);
}

static inline uint32_t epc(csx_test_p t)
{
	return(pc(t) + 8);
}

static inline int32_t eao(csx_test_p t, int32_t ieao)
{
	/* (((offset - 8) >> 2) & 0x00ffffff) */

	int32_t ea = (ieao << 2) - 4;
	
	if(0) LOG("ea = 0x%08x", ea);
	
	return(ea);
}

static void csx_test_arm_mov(csx_test_p t)
{
	csx_core_p core = t->core;
	
	csx_reg_set(core, rPC, 0);
	arm_mov_rn_rd_sop(t, 0, 0, 0);
	csx_test_run(t, 0, csx_reg_get(core, INSN_PC), 1);
	assert(0x00000000 == csx_reg_get(core, 0));

	csx_reg_set(core, rPC, 0);
	arm_mov_rn_rd_sop(t, 0, 0, 64);
	csx_test_run(t, 0, csx_reg_get(core, INSN_PC), 1);
	assert(0x00000040 == csx_reg_get(core, 0));

	csx_reg_set(core, rPC, 0);
	arm_mov_rn_rd_sop(t, 0, 1, arm_dpi_ror_i_s(64, 26));
	csx_test_run(t, 0, csx_reg_get(core, INSN_PC), 1);
	assert(0x00000000 == csx_reg_get(core, 0));
	assert(0x00001000 == csx_reg_get(core, 1));
}

void csx_test_arm(csx_test_p t)
{
//	csx_test_arm_b(t);
	csx_test_arm_mov(t);
}
