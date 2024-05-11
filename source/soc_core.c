#include "config.h"
#include "soc_core.h"

#include "soc_core_trace.h"

/* **** */

#include "csx_coprocessor.h"
#include "csx_statistics.h"
#include "csx_soc_exception.h"
#include "csx_soc.h"
#include "csx_test_utility.h"

#include "arm_cpsr.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

static int _soc_core_atexit(void* param)
{
	if(_trace_atexit) {
		LOG(">>");
	}

	handle_free(param);

	if(_trace_atexit_pedantic) {
		LOG("<<");
	}

	return(0);
}

static int _soc_core_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	// TODO: bootrom

	soc_core_p core = param;

	for(int i = 0; i < 16; i++)
//		soc_core_reg_set(core, i, 0);
		soc_core_reg_set(core, i, ((~0UL) << 16) | _test_value(i));

	CPSR = CPSR_M32(Supervisor);
	soc_core_exception(core, _EXCEPTION_Reset);

	return(0);
}

soc_core_p soc_core_alloc(csx_p csx, csx_soc_p soc, soc_core_h h2core)
{
	ERR_NULL(csx);
	ERR_NULL(soc);
	ERR_NULL(h2core);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_core_p core = HANDLE_CALLOC(h2core, 1, sizeof(soc_core_t));
	ERR_NULL(core);

	core->csx = csx;
	core->soc = soc;

	/* **** */

	csx_soc_callback_atexit(soc, &core->atexit, _soc_core_atexit, h2core);
	csx_soc_callback_atreset(soc, &core->atreset, _soc_core_atreset, core);

	/* **** */

	return(core);
}

void soc_core_init(soc_core_p core)
{
	ERR_NULL(core);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	core->mmu = core->soc->mmu;
}

void soc_core_reset(soc_core_p core)
{
	if(_trace_atreset) {
		LOG();
	}

	_soc_core_atreset(core);
}
