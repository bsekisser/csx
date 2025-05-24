#pragma once

typedef struct csx_statistics_tag** csx_statistics_hptr;
typedef csx_statistics_hptr const csx_statistics_href;

typedef struct csx_statistics_tag* csx_statistics_ptr;
typedef csx_statistics_ptr const csx_statistics_ref;

extern csx_statistics_ptr statistics;

/* **** */

#include "config.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"
#include "libbse/include/dtime.h"

/* **** */

#include <stdint.h>

/* **** */

typedef struct csx_counter_hit_tag* csx_counter_hit_ptr;
typedef csx_counter_hit_ptr const csx_counter_hit_ref;

typedef struct csx_counter_hit_tag {
	uint32_t hit;
	uint32_t miss;
}csx_counter_hit_t;

typedef struct csx_statistic_counters_tag {
	struct {
		uint32_t read;
		uint32_t write;
	}mmio;
}csx_statistic_counters_t;

/* **** */

typedef struct csx_profile_stat_tag* csx_profile_stat_ptr;
typedef csx_profile_stat_ptr const csx_profile_stat_ref;

typedef struct csx_profile_stat_tag {
	uint32_t count;
	uint64_t elapsed;
}csx_profile_stat_t;

typedef struct csx_statistic_profile_tag {
}csx_statistic_profile_t;

typedef struct csx_statistics_tag {
	csx_ptr csx;
	csx_statistic_counters_t counters;
	csx_statistic_profile_t profile;
}csx_statistics_t;

/* **** */

extern action_list_t csx_statistics_action_list;

csx_statistics_ptr csx_statistics_alloc(csx_ref csx, csx_statistics_href h2s);

static inline void csx_counter_add(uint32_t* c, unsigned add) {
	if(_csx_statistical_counters)
		*c += add;
}

static inline void csx_counter_inc(uint32_t* c) {
	if(_csx_statistical_counters)
		(*c)++;
}

static inline void csx_counter_hit_if(csx_counter_hit_ref c, unsigned test) {
	if(_csx_statistical_counters) {
		if(test)
			c->hit++;
		else
			c->miss++;
	}
}

/* **** */

#ifndef CSX_COUNTERS
	#define CSX_COUNTERS(_x) _x
#endif

#define CSX_COUNTER_MEMBER(_member) statistics->counters._member

#define CSX_COUNTER_ADD(_c, _add) \
	({ CSX_COUNTERS(csx_counter_add(&CSX_COUNTER_MEMBER(_c), _add)); )}

#define CSX_COUNTER_INC(_c) \
	({ CSX_COUNTERS(csx_counter_inc(&CSX_COUNTER_MEMBER(_c))); })

#define CSX_COUNTER_HIT_IF(_c, _test) \
	({ CSX_COUNTERS(csx_counter_hit_if(&CSX_COUNTER_MEMBER(_c), _test)); })

/* **** */

static inline void csx_profile_stat_count(csx_profile_stat_ref s, uint64_t dtime) {
	if(_csx_statistical_counters) {
		s->count++;
		s->elapsed += _get_dtime_elapsed(dtime);
	}
}

#ifndef CSX_PROFILE
	#define CSX_PROFILE(_x) _x
#endif

#define CSX_PROFILE_MEMBER(_member) statistics->profile._member

#define CSX_PROFILE_STAT_COUNT(_member, _dtime) \
	({ CSX_PROFILE(csx_profile_stat_count(&CSX_PROFILE_MEMBER(_member), dtime)); })
