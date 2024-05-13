#include "csx_cache.h"

/* **** */

typedef struct csx_cache_t {
	// empty
}csx_cache_t;

/* **** */

#include "csx.h"
#include "csx_armvm_glue.h"

/* **** */

#include "libarmvm/include/armvm_coprocessor.h"
#include "libarmvm/include/armvm_coprocessor_glue.h"
#include "libarmvm/include/armvm_core_exception.h"
#include "libarmvm/include/armvm_exception.h"

#include "libarmvm/include/armvm.h"

#include "libarm/include/arm_cpsr.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/log.h"

/* **** */

#undef DEBUG
//#define DEBUG(_x) _x
#ifndef DEBUG
	#define DEBUG(_x)
#endif

#define IF_USER_MODE(_action) \
	if(IS_USER_MODE) { \
		LOG_ACTION(_action); \
	}

#define IS_USER_MODE (0 == soc_core_in_a_privaleged_mode(csx))

/* **** */

static uint32_t _csx_cache_cp15_0_7_0_4_access(void* param, uint32_t* write)
{
	const csx_p csx = param;

//	armvm_exception_fiq(csx->armvm);
//	armvm_exception_irq(csx->armvm);
	armvm_core_exception_reset(csx->armvm->core);
//	armvm_core_exception_swi(csx->armvm->core);
	return(0);
}

static uint32_t _csx_cache_cp15_0_7_5_0_access(void* param, uint32_t* write)
{
	const csx_p csx = param;

	if(write) {
		IF_USER_MODE(armvm_core_exception_undefined_instruction(csx->armvm->core));
		LOG("Invalidate ICache");
	} else {
		DEBUG(LOG("XX READ -- Invalidate ICache"));
	}

	return(0);
}

static uint32_t _csx_cache_cp15_0_7_6_0_access(void* param, uint32_t* write)
{
	const csx_p csx = param;

	if(write) {
		IF_USER_MODE(armvm_core_exception_undefined_instruction(csx->armvm->core));
		LOG("Invalidate DCache");
	} else {
		DEBUG(LOG("XX READ -- Invalidate DCache"));
	}

	return(0);
}


static uint32_t _csx_cache_cp15_0_7_7_0_access(void* param, uint32_t* write)
{
	const csx_p csx = param;

	if(write) {
		IF_USER_MODE(armvm_core_exception_undefined_instruction(csx->armvm->core));
		LOG("Invalidate ICache and DCache");
	} else {
		DEBUG(LOG("XX READ -- Invalidate ICache and DCache"));
	}

	return(0);
}

static uint32_t _csx_cache_cp15_0_7_10_3_access(void* param, uint32_t* write)
{
//	const csx_p csx = param;

	uint32_t data = write ? *write : 0;

	if(write) {
		DEBUG(LOG("Cache, Test and Clean"));
	} else {
		LOG("Cache, Test and Clean");
		ARM_CPSRx_BSET(data, Z);
	}

	return(data);
	UNUSED(param);
}

static uint32_t _csx_cache_cp15_0_7_10_4_access(void* param, uint32_t* write)
{
	const csx_p csx = param;

	if(write) {
		IF_USER_MODE(armvm_core_exception_undefined_instruction(csx->armvm->core));
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
	const armvm_coprocessor_p cp = csx->armvm->coprocessor;

	armvm_coprocessor_register_callback(cp, cp15(0, 7, 0, 4),
		_csx_cache_cp15_0_7_0_4_access, cache);
	armvm_coprocessor_register_callback(cp, cp15(0, 7, 5, 0),
		_csx_cache_cp15_0_7_5_0_access, cache);
	armvm_coprocessor_register_callback(cp, cp15(0, 7, 6, 0),
		_csx_cache_cp15_0_7_6_0_access, cache);
	armvm_coprocessor_register_callback(cp, cp15(0, 7, 7, 0),
		_csx_cache_cp15_0_7_7_0_access, cache);
	armvm_coprocessor_register_callback(cp, cp15(0, 7, 10, 3),
		_csx_cache_cp15_0_7_10_3_access, cache);
	armvm_coprocessor_register_callback(cp, cp15(0, 7, 10, 4),
		_csx_cache_cp15_0_7_10_4_access, cache);
}
