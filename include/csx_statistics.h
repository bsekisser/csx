#pragma once

typedef struct csx_statistics_t** csx_statistics_h;
typedef struct csx_statistics_t* csx_statistics_p;

extern csx_statistics_p statistics;

extern int _profile_soc_core_ifetch;
extern int _profile_soc_core_read;
extern int _profile_soc_core_step_arm;
extern int _profile_soc_core_step_thumb;
extern int _profile_soc_core_write;

/* **** */

#include "config.h"
#include "csx.h"

/* **** */

#include "dtime.h"

/* **** */

#include <stdint.h>

/* **** */

typedef struct csx_counter_hit_t* csx_counter_hit_p;
typedef struct csx_counter_hit_t {
	uint32_t hit;
	uint32_t miss;
}csx_counter_hit_t;

typedef struct csx_statistic_counters_t {
	struct {
		uint32_t read;
		struct {
			uint32_t cdp;
			uint32_t count;
			uint32_t flash;
			uint32_t framebuffer;
			uint32_t sdram;
		}read_ppa;
		uint32_t write;
		struct {
			uint32_t cdp;
			uint32_t count;
			uint32_t flash;
			uint32_t framebuffer;
			uint32_t sdram;
		}write_ppa;
	}csx_soc;
	struct {
		uint32_t read;
		uint32_t write;
	}mmio;
	struct {
		csx_counter_hit_t ifetch;
		csx_counter_hit_t read;
		csx_counter_hit_t write;
	}soc_tlb;
}csx_statistic_counters_t;

/* **** */

typedef struct csx_profile_stat_t* csx_profile_stat_p;
typedef struct csx_profile_stat_t {
	uint32_t count;
	uint64_t elapsed;
}csx_profile_stat_t;

typedef struct csx_statistic_profile_t {
	struct {
		csx_profile_stat_t ifetch;
		csx_profile_stat_t read;
		struct {
			csx_profile_stat_t arm;
			csx_profile_stat_t thumb;
		}step;
		csx_profile_stat_t write;
	}soc_core;
}csx_statistic_profile_t;

/* **** */

typedef struct csx_statistics_t {
	csx_p csx;
	csx_statistic_counters_t counters;
	csx_statistic_profile_t profile;
}csx_statistics_t;

/* **** */

int csx_statistics_init(csx_p csx);

static inline void csx_counter_add(uint32_t* c, uint add) {
	if(_csx_statistical_counters)
		*c += add;
}

static inline void csx_counter_inc(uint32_t* c) {
	if(_csx_statistical_counters)
		(*c)++;
}

static inline void csx_counter_hit_if(csx_counter_hit_p c, uint test) {
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
	#define CSX_COUNTER_MEMBER(_member) statistics->counters._member
#endif

#define CSX_COUNTER_ADD(_c, _add) \
	CSX_COUNTERS(csx_counter_add(&CSX_COUNTER_MEMBER(_c), _add);)

#define CSX_COUNTER_INC(_c) \
	CSX_COUNTERS(csx_counter_inc(&CSX_COUNTER_MEMBER(_c));)

#define CSX_COUNTER_HIT_IF(_c, _test) \
	CSX_COUNTERS(csx_counter_hit_if(&CSX_COUNTER_MEMBER(_c), _test);)

/* **** */

static inline void csx_profile_stat_count(csx_profile_stat_p s, uint64_t dtime) {
	s->count++;
	s->elapsed += _get_dtime_elapsed(dtime);
}

#ifndef CSX_PROFILE
	#define CSX_PROFILE(_x) _x
	#define CSX_PROFILE_MEMBER(_member) statistics->profile._member
#endif

#define CSX_PROFILE_STAT_COUNT(_member, _dtime) \
	csx_profile_stat_count(&CSX_PROFILE_MEMBER(_member), dtime)
