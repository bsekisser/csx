#include "csx.h"
#include "csx_core.h"

#include "csx_core_arm.h"

void csx_core_reset(csx_core_p core)
{
	_TRACE_(core, ENTER);
	
	CPSR = 0x13;			/* Enter Supervisor mode */
	BIT_CLEAR(CPSR, 5); /* Execute in ARM state */
	BIT_SET(CPSR, 6);	/* Disable fast interrupts */
	BIT_SET(CPSR, 7);	/* Disable normal interrupts */
//	BIT_SET(CPSR, 8);	/* Disable Imprecise Aborts (v6 only) */
	BIT_SET(CPSR, 9);	/* Endianness on exception entry */
	
#if 0
	csx_reg_set(core, INSN_PC, 0xffff0000);	/* if high vectors */
#else
	csx_reg_set(core, INSN_PC, 0);
#endif

	csx_trace_psr(core, __FUNCTION__, CPSR);
	
	core->csx->step = csx_core_arm_step;
	
	_TRACE_(core, EXIT);
}

int csx_core_init(csx_p csx)
{
	_TRACE_(csx, ENTER);
	
	int err;

	csx_core_p core;
	ERR_NULL(core = malloc(sizeof(csx_core_t)));

	core->csx = csx;
	csx->core = core;

	ERR(err = csx_coprocessor_init(csx));
	ERR(err = csx_mmu_init(csx));
	ERR(err = csx_mmio_init(csx));

	csx_core_reset(core);

	_TRACE_(csx, EXIT);
	return(err);
}
