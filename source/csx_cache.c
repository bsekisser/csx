#include "csx_cache.h"

/* **** */

typedef struct csx_cache_t {
	// empty
}csx_cache_t;

/* **** */

#include "soc_core_psr.h"

/* **** */

#include "csx_coprocessor.h"
#include "csx.h"

/* **** */

#include "bitfield.h"

/* **** */

#undef DEBUG
//#define DEBUG(_x) _x
#ifndef DEBUG
	#define DEBUG(_x)
#endif

#define IF_USER_MODE(_action) \
	if(IS_USER_MODE) { \
		_action; \
	}

#define IS_USER_MODE (0 == soc_core_in_a_privaleged_mode(core))

/* **** */

static uint32_t _csx_cache_cp15_0_7_5_0_access(void* param, uint32_t* write)
{
	const csx_p csx = param;
	const soc_core_p core = csx->core;

	if(write) {
		IF_USER_MODE(soc_core_exception(core, _EXCEPTION_UndefinedInstruction));
		LOG("Invalidate ICache");
	} else {
		DEBUG(LOG("XX READ -- Invalidate ICache"));
	}

	return(0);
}

static uint32_t _csx_cache_cp15_0_7_7_0_access(void* param, uint32_t* write)
{
	const csx_p csx = param;
	const soc_core_p core = csx->core;

	if(write) {
		IF_USER_MODE(soc_core_exception(core, _EXCEPTION_UndefinedInstruction));
		LOG("Invalidate ICache and DCache");
	} else {
		DEBUG(LOG("XX READ -- Invalidate ICache and DCache"));
	}

	return(0);
}

static uint32_t _csx_cache_cp15_0_7_10_3_access(void* param, uint32_t* write)
{
	const csx_p csx = param;
	const soc_core_p core = csx->core;

	uint32_t data = write ? *write : 0;
	
	if(write) {
		DEBUG(LOG("Cache, Test and Clean"));
	} else {
		LOG("Cache, Test and Clean");
		data = (CPSR & SOC_CORE_PSR_NZCV) | SOC_CORE_PSR_Z;
	}

	return(data);
}

static uint32_t _csx_cache_cp15_0_7_10_4_access(void* param, uint32_t* write)
{
	const csx_p csx = param;
	const soc_core_p core = csx->core;

	if(write) {
		IF_USER_MODE(soc_core_exception(core, _EXCEPTION_UndefinedInstruction));
		LOG("Drain write buffer");
	} else {
		DEBUG(LOG("XX READ -- Drain write buffer"));
	}

	return(0);
}

/* **** */

csx_cache_p csx_cache_alloc(csx_p csx, csx_cache_h h2cache)
{
	ERR_NULL(csx);
	ERR_NULL(h2cache);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	*h2cache = (void*)csx;

	/* **** */

	return((void*)csx);
}

void csx_cache_init(csx_cache_p cache)
{
	ERR_NULL(cache);

	if(_trace_init) {
		LOG();
	}

	const csx_p csx = (void*)cache;
	const csx_coprocessor_p cp = csx->cp;

	csx_coprocessor_register_access(cp, cp15(0, 7, 5, 0),
		_csx_cache_cp15_0_7_5_0_access, cache);
	csx_coprocessor_register_access(cp, cp15(0, 7, 7, 0),
		_csx_cache_cp15_0_7_7_0_access, cache);
	csx_coprocessor_register_access(cp, cp15(0, 7, 10, 3),
		_csx_cache_cp15_0_7_10_3_access, cache);
	csx_coprocessor_register_access(cp, cp15(0, 7, 10, 4),
		_csx_cache_cp15_0_7_10_4_access, cache);
}
