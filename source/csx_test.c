#include "csx_test.h"
#include "csx_test_arm.h"
#include "csx_test_thumb.h"
#include "csx_test_utility.h"

#include "soc.h"
#include "soc_core_psr.h"

/* **** */

#include "err_test.h"
#include "bitfield.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

uint32_t _csx_test_run(csx_test_p t, uint32_t start_pc, uint32_t end_pc, uint32_t count)
{
	const csx_p csx = t->csx;
	const soc_core_p core = csx->core;

	if(0) LOG("start_pc = 0x%08x thumb = %u", start_pc, !!(CPSR & SOC_CORE_PSR_T));

	csx->state = CSX_STATE_RUN;

	soc_core_reg_set_pcx(core, start_pc);
	for(; count ; count--)
	{
		csx->cycle++;
		core->step(core);

		if(PC >= end_pc)
			break;

		csx->insns++;
	}

	csx->state = CSX_STATE_HALT;

	return(PC);
}

uint32_t csx_test_run(csx_test_p t, uint32_t count)
{
	return(_csx_test_run(t, t->start_pc, pc(t), count));
}

uint32_t csx_test_run_thumb(csx_test_p t, uint32_t count)
{
	return(_csx_test_run(t, t->start_pc | 1, pc(t), count));
}

int csx_test_main(csx_p csx, int core_trace)
{
	csx_test_p t = calloc(1, sizeof(csx_test_t));
	ERR_NULL(t);

	t->csx = csx;

	csx->core->trace = core_trace;

	t->start_pc = CSX_SDRAM_BASE;
	csx->state = CSX_STATE_HALT;

	csx_test_arm(t);
	csx_test_thumb(t);

	return(0);
}
