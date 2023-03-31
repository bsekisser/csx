#include "config.h"
#include "soc_core.h"

#include "soc_core_trace.h"
#include "soc.h"

/* **** */

#include "csx_statistics.h"
#include "csx_test_utility.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

static int _soc_core_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}
	
	handle_free(param);
	
	return(0);
}

static int _soc_core_reset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	// TODO: bootrom

	soc_core_p core = param;

	for(int i = 0; i < 16; i++)
		soc_core_reg_set(core, i, ((~0UL) << 16) | _test_value(i));

	CPSR = 0x13;		/* Enter Supervisor mode */
	BCLR(CPSR, 5);		/* Execute in ARM state */
	BSET(CPSR, 6);		/* Disable fast interrupts */
	BSET(CPSR, 7);		/* Disable normal interrupts */
	BSET(CPSR, 8);		/* Disable Imprecise Aborts (v6 only) */
	BSET(CPSR, 9);		/* Endianness on exception entry */
	
	const int high_vectors = 0;
	uint32_t reset_pc = !high_vectors ? 0 : 0xffff0000;	/* if high vectors */

	if(core->csx->cdp)
		reset_pc = core->csx->cdp->base;

	soc_core_psr_mode_switch(core, CPSR);
	soc_core_reg_set_pcx(core, reset_pc);

	soc_core_trace_psr(core, __FUNCTION__, CPSR);
	return(0);
}

int soc_core_in_a_privaleged_mode(soc_core_p core)
{
	return(0x00 != mlBFEXT(CPSR, 4, 0));
}

int soc_core_init(csx_p csx, soc_core_h h2core)
{
	if(_trace_init) {
		LOG();
	}

	// TODO: move to csx_soc

	int err = 0;

	soc_core_p core = HANDLE_CALLOC(h2core, 1, sizeof(soc_core_t));
	ERR_NULL(core);

	core->csx = csx;

	csx_soc_callback_atexit(csx->soc, _soc_core_atexit, h2core);
	csx_soc_callback_atreset(csx->soc, _soc_core_reset, core);

	/* **** */

//	soc_core_reset(core);

	return(err);
}

void soc_core_reset(soc_core_p core)
{
	_soc_core_reset(core);
}
