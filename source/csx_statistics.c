#include "csx_statistics.h"

/* **** */

#include "handle.h"
#include "log.h"

/* **** */

#include <stdint.h>

/* **** */

csx_statistics_p statistics;

#define STRINGIFY(_x) #_x

/* **** */

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
	COUNTER_LIST_ ## _action(csx_soc.read) \
	COUNTER_LIST_ ## _action(csx_soc.read_ppa.cdp) \
	COUNTER_LIST_ ## _action(csx_soc.read_ppa.count) \
	COUNTER_LIST_ ## _action(csx_soc.read_ppa.flash) \
	COUNTER_LIST_ ## _action(csx_soc.read_ppa.framebuffer) \
	COUNTER_LIST_ ## _action(csx_soc.read_ppa.sdram) \
	\
	COUNTER_LIST_ ## _action(csx_soc.write) \
	COUNTER_LIST_ ## _action(csx_soc.write_ppa.cdp) \
	COUNTER_LIST_ ## _action(csx_soc.write_ppa.count) \
	COUNTER_LIST_ ## _action(csx_soc.write_ppa.flash) \
	COUNTER_LIST_ ## _action(csx_soc.write_ppa.framebuffer) \
	COUNTER_LIST_ ## _action(csx_soc.write_ppa.sdram) \
	\
	COUNTER_LIST_ ## _action(mmio.read) \
	COUNTER_LIST_ ## _action(mmio.write) \
	\
	COUNTER_LIST_ ## _action ## _HIT(soc_tlb.ifetch) \
	COUNTER_LIST_ ## _action ## _HIT(soc_tlb.read) \
	COUNTER_LIST_ ## _action ## _HIT(soc_tlb.write) \

/* **** */

static int _csx_statistics_atexit(void* param) {
//	csx_statistics_h h2c = param;
//	csx_statistics_p c = *h2c;

	COUNTER_LIST(LOG);
	PROFILE_LIST(LOG);
	
	handle_free(param);

	return(0);
}

static int _csx_statistics_atreset(void* param) {
//	csx_statistics_p c = param;

	COUNTER_LIST(ZERO);
	PROFILE_LIST(ZERO);

	return(0);

	UNUSED(param);
}

/* **** */ 

int csx_statistics_init(csx_p csx)
{
	statistics = calloc(1, sizeof(csx_statistics_t));

	statistics->csx = csx;

	/* **** */

	csx_callback_atexit(csx, _csx_statistics_atexit, &statistics);
	csx_callback_atreset(csx, _csx_statistics_atreset, statistics);

	return(0);
}
