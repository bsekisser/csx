#include "csx.h"
#include "soc_core.h"
#include "soc_trace.h"

#include "soc_core_arm.h"

void soc_core_reset(soc_core_p core)
{
	_TRACE_(core, ENTER);
	
	CPSR = 0x13;		/* Enter Supervisor mode */
	BCLR(CPSR, 5);		/* Execute in ARM state */
	BSET(CPSR, 6);		/* Disable fast interrupts */
	BSET(CPSR, 7);		/* Disable normal interrupts */
	BSET(CPSR, 8);		/* Disable Imprecise Aborts (v6 only) */
	BSET(CPSR, 9);		/* Endianness on exception entry */
	
	const int high_vectors = 0;
	uint32_t reset_pc = !high_vectors ? 0 : 0xffff0000;	/* if high vectors */

	reset_pc = 0x10020000;

	soc_core_reg_set_pcx(core, reset_pc);

	soc_trace_psr(core, __FUNCTION__, CPSR);

	soc_core_psr_mode_switch(core, CPSR);
	
	_TRACE_(core, EXIT);
}

int soc_core_init(csx_p csx, soc_core_h h2core)
{
	int err = 0;

	soc_core_p core;
	ERR_NULL(core = malloc(sizeof(soc_core_t)));

	_TRACE_(core, ENTER);

	core->csx = csx;
	*h2core = core;

	soc_core_reset(core);

	_TRACE_(core, EXIT);
	return(err);
}
