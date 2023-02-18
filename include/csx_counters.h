#pragma once

typedef struct csx_counters_t** csx_counters_h;
typedef struct csx_counters_t* csx_counters_p;

extern csx_counters_p counters;

/* **** */

#include "config.h"
#include "csx.h"

/* **** */

#include <stdint.h>

/* **** */

typedef struct csx_counter_hit_t* csx_counter_hit_p;
typedef struct csx_counter_hit_t {
	uint32_t hit;
	uint32_t miss;
}csx_counter_hit_t;

typedef struct csx_counters_t {
	csx_p csx;

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
}csx_counters_t;

/* **** */

int csx_counters_init(csx_p csx);

static inline void csx_counter_add(uint32_t* c, uint add) {
	if(_performance_counters)
		*c += add;
}

static inline void csx_counter_inc(uint32_t* c) {
	if(_performance_counters)
		(*c)++;
}

static inline void csx_counter_hit_if(csx_counter_hit_p c, uint test) {
	if(_performance_counters) {
		if(test)
			c->hit++;
		else
			c->miss++;
	}
}

/* **** */

#ifndef COUNTERS
	#define COUNTERS(_x) _x
#endif

#define CSX_COUNTER_ADD(_c, _add) \
	COUNTERS(csx_counter_add(&counters->_c, _add);)

#define CSX_COUNTER_INC(_c) \
	COUNTERS(csx_counter_inc(&counters->_c);)

#define CSX_COUNTER_HIT_IF(_c, _test) \
	COUNTERS(csx_counter_hit_if(&counters->_c, _test);)

/* **** */
