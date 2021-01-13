#include "csx.h"
#include "csx_core.h"
#include "csx_trace.h"

#include "csx_core_arm.h"

void csx_core_reset(csx_core_p core)
{
	_TRACE_(core, ENTER);
	
	CPSR = 0x13;			/* Enter Supervisor mode */
	BCLR(CPSR, 5); /* Execute in ARM state */
	BSET(CPSR, 6);	/* Disable fast interrupts */
	BSET(CPSR, 7);	/* Disable normal interrupts */
//	BSET(CPSR, 8);	/* Disable Imprecise Aborts (v6 only) */
	BSET(CPSR, 9);	/* Endianness on exception entry */
	
#if 0
	csx_reg_set(core, INSN_PC, 0xffff0000);	/* if high vectors */
#else
	csx_reg_set(core, INSN_PC, 0);
#endif

	csx_trace_psr(core, __FUNCTION__, CPSR);
	
	core->step = csx_core_arm_step;
	
	_TRACE_(core, EXIT);
}

int csx_core_init(csx_p csx, csx_core_h h2core)
{
	int err = 0;

	csx_core_p core;
	ERR_NULL(core = malloc(sizeof(csx_core_t)));

	_TRACE_(core, ENTER);

	core->csx = csx;
	*h2core = core;

	csx_core_reset(core);

	_TRACE_(core, EXIT);
	return(err);
}
