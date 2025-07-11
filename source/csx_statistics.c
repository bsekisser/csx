#include "csx_statistics.h"

/* **** */

#include "libbse/include/action.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/unused.h"

/* **** */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

csx_statistics_ptr statistics;

#define STRINGIFY(_x) #_x

/* **** */

UNUSED_FN
static void _stat_profile_assert_zero(csx_profile_stat_ref s, const char* name) {
	int fail = (0 != s->count);
	fail |= (0 != s->elapsed);

	if(fail) {
		LOG("assert(fail -- %s)", name);
	}
}

UNUSED_FN
static void _stat_profile_clear(csx_profile_stat_ref s) {
	s->count = 0;
	s->elapsed = 0;
}

UNUSED_FN
static void _stat_profile_log(csx_profile_stat_ref s, const char* name) {
	const uint32_t count = s->count ?: 1;

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

#define PROFILE_LIST(_action)

/* **** */

static void _stat_counter_log(const uint32_t c, const char* name) {
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
	COUNTER_LIST_ ## _action(mmio.read) \
	COUNTER_LIST_ ## _action(mmio.write)

/* **** */

static
int csx_statistics_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

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

	/* **** */

	handle_ptrfree(param);

	return(err);
}

static
int csx_statistics_action_reset(int err, void *const param, action_ref)
{
	ACTION_LOG(reset);

	/* **** */

//	csx_statistics_ref c = param;

	COUNTER_LIST(ZERO);
	PROFILE_LIST(ZERO);

	/* **** */

	return(err);
	UNUSED(param);
}

/* **** */

static
action_linklist_t csx_statistics_action_linklist[] = {
	{ offsetof(csx_statistics_t, csx), csx },
	{ 0, 0 },
};

ACTION_LIST(csx_statistics_action_list,
	.link = csx_statistics_action_linklist,
	.list = {
		[_ACTION_EXIT] = {{ csx_statistics_action_exit }, { 0 }, 0 },
		[_ACTION_RESET] = {{ csx_statistics_action_reset }, { 0 }, 0, },
	}
);

csx_statistics_ptr csx_statistics_alloc(csx_statistics_href h2s)
{
	ACTION_LOG(alloc);
	ERR_NULL(h2s);

	/* **** */

	statistics = handle_calloc(h2s, 1, sizeof(csx_statistics_t));
	ERR_NULL(statistics);

	/* **** */

	return(statistics);
}
