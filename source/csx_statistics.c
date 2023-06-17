#include "csx_statistics.h"

/* **** */

#include "callback_qlist.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"
#include "unused.h"

/* **** */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

csx_statistics_p statistics;

#define STRINGIFY(_x) #_x

/* **** */

static void _stat_profile_assert_zero(csx_profile_stat_p s, const char* name) {
	int fail = (0 != s->count);
	fail |= (0 != s->elapsed);
	
	if(fail) {
		LOG("assert(fail -- %s)", name);
	}
}

static void _stat_profile_clear(csx_profile_stat_p s) {
	s->count = 0;
	s->elapsed = 0;
}

static void _stat_profile_log(csx_profile_stat_p s, const char* name) {
	uint32_t count = s->count ?: 1;

	LOG_ERR("count = 0x%08x, elapsed = 0x%016" PRIx64 " dtime/count = 0x%016" PRIx64 " -- %s",
		s->count, s->elapsed, (s->elapsed / count), name);
}

#define _PROFILE_NAME(_member) STRINGIFY(profile._member)

#define PROFILE_LIST_ASSERT_ZERO(_member) \
	_stat_profile_assert_zero(&CSX_PROFILE_MEMBER(_member), _PROFILE_NAME(_member));
	
#define PROFILE_LIST_LOG(_member) \
	_stat_profile_log(&CSX_PROFILE_MEMBER(_member), _PROFILE_NAME(_member));

#define PROFILE_LIST_ZERO(_member) \
	_stat_profile_clear(&CSX_PROFILE_MEMBER(_member));

#define PROFILE_LIST(_action) \
	PROFILE_LIST_ ## _action(csx_mem_access.sdram) \
	PROFILE_LIST_ ## _action(csx_mem_access.generic) \
	PROFILE_LIST_ ## _action(csx_mem_access.generic_ro) \
	PROFILE_LIST_ ## _action(soc_core.ifetch) \
	PROFILE_LIST_ ## _action(soc_core.read) \
	PROFILE_LIST_ ## _action(soc_core.step.arm) \
	PROFILE_LIST_ ## _action(soc_core.step.thumb) \
	PROFILE_LIST_ ## _action(soc_core.write) \

/* **** */

static void _stat_counter_log(uint32_t c, const char* name) {
	LOG_ERR("0x%08x -- %s", c, name);
}

#define _COUNTER_NAME(_member) STRINGIFY(counters._member)

#define COUNTER_LIST_ASSERT_ZERO(_member) \
	assert(0 == CSX_COUNTER_MEMBER(_member));

#define COUNTER_LIST_ASSERT_ZERO_HIT(_member) \
	COUNTER_LIST_ASSERT_ZERO(_member.hit) \
	COUNTER_LIST_ASSERT_ZERO(_member.hit) \

#define COUNTER_LIST_LOG(_member) \
	_stat_counter_log(CSX_COUNTER_MEMBER(_member), _COUNTER_NAME(_member));

#define COUNTER_LIST_LOG_HIT(_member) \
	COUNTER_LIST_LOG(_member.hit) \
	COUNTER_LIST_LOG(_member.miss) \

#define COUNTER_LIST_ZERO(_member) \
	CSX_COUNTER_MEMBER(_member) = 0;

#define COUNTER_LIST_ZERO_HIT(_member) \
	COUNTER_LIST_ZERO(_member.hit) \
	COUNTER_LIST_ZERO(_member.miss) \

#define COUNTER_LIST(_action) \
	COUNTER_LIST_ ## _action(csx_mem_access.sdram.read) \
	COUNTER_LIST_ ## _action(csx_mem_access.sdram.write) \
	COUNTER_LIST_ ## _action(csx_mem_access.generic.read) \
	COUNTER_LIST_ ## _action(csx_mem_access.generic.write) \
	COUNTER_LIST_ ## _action(csx_mem_access.generic.ro) \
	COUNTER_LIST_ ## _action(csx_mem_access.generic.ro_write) \
	\
	COUNTER_LIST_ ## _action(mmio.read) \
	COUNTER_LIST_ ## _action(mmio.write) \
	\
	COUNTER_LIST_ ## _action ## _HIT(soc.tlb.ifetch) \
	COUNTER_LIST_ ## _action ## _HIT(soc.tlb.read) \
	COUNTER_LIST_ ## _action ## _HIT(soc.tlb.write) \

/* **** */

static int _csx_statistics_atexit(void* param) {
	if(_trace_atexit) {
		LOG(">>");
	}

//	csx_statistics_h h2c = param;
//	csx_statistics_p c = *h2c;

	if(_csx_statistical_counters) {
		COUNTER_LIST(LOG);
	} else {
		COUNTER_LIST(ASSERT_ZERO);
	}

	if(_csx_statistical_profile) {
		PROFILE_LIST(LOG);
	} else {
		PROFILE_LIST(ASSERT_ZERO);
	}
	
	if(_trace_atexit_pedantic) {
		LOG("--");
	}

	handle_free(param);

	if(_trace_atexit_pedantic) {
		LOG("<<");
	}

	return(0);
}

static int _csx_statistics_atreset(void* param) {
	if(_trace_atreset) {
		LOG();
	}

//	csx_statistics_p c = param;

	COUNTER_LIST(ZERO);
	PROFILE_LIST(ZERO);

	return(0);
	UNUSED(param);
}

/* **** */ 

csx_statistics_p csx_statistics_alloc(csx_p csx, csx_statistics_h h2s)
{
	statistics = handle_calloc((void**)h2s, 1, sizeof(csx_statistics_t));
	ERR_NULL(statistics);
	
	statistics->csx = csx;

	/* **** */

	csx_callback_atexit(csx, &statistics->atexit, _csx_statistics_atexit, h2s);
	csx_callback_atreset(csx, &statistics->atreset, _csx_statistics_atreset, statistics);

	return(statistics);
}

void csx_statistics_init(csx_statistics_p s)
{
	UNUSED(s);
}
