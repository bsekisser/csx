#include "csx_counters.h"

/* **** */

#include "handle.h"
#include "log.h"

/* **** */

#include <stdint.h>

/* **** */

csx_counters_p counters;

#define COUNTER_LIST_LOG(_member) \
	LOG_ERR("0x%08x -- " #_member, counters->_member);

#define COUNTER_LIST_HIT_LOG(_member) \
	COUNTER_LIST_LOG(_member.hit) \
	COUNTER_LIST_LOG(_member.miss) \

#define COUNTER_LIST_ZERO(_member) \
	counters->_member = 0;

#define COUNTER_LIST_HIT_ZERO(_member) \
	counters->_member.hit = 0; \
	counters->_member.miss = 0; \

#define COUNTER_LIST(_action) \
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
	COUNTER_LIST_HIT_ ## _action(soc_tlb.ifetch) \
	COUNTER_LIST_HIT_ ## _action(soc_tlb.read) \
	COUNTER_LIST_HIT_ ## _action(soc_tlb.write) \

/* **** */

static int _csx_counters_atexit(void* param) {
//	csx_counters_h h2c = param;
//	csx_counters_p c = *h2c;

	COUNTER_LIST(LOG);
	
	handle_free(param);

	return(0);
}

static int _csx_counters_atreset(void* param) {
//	csx_counters_p c = param;

	COUNTER_LIST(ZERO);

	return(0);

	UNUSED(param);
}

/* **** */ 

int csx_counters_init(csx_p csx)
{
	counters = calloc(1, sizeof(csx_counters_t));

	counters->csx = csx;

	/* **** */

	csx_callback_atexit(csx, _csx_counters_atexit, &counters);
	csx_callback_atreset(csx, _csx_counters_atreset, counters);

	return(0);
}
