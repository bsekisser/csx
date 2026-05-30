#pragma once

/* **** */

typedef struct csx_tag* csx_ptr;
typedef csx_ptr const csx_ref;

typedef struct csx_tag** csx_hptr;
typedef csx_hptr const csx_href;

typedef struct csx_data_tag* csx_data_ptr;
typedef csx_data_ptr const csx_data_ref;

typedef union csx_option_tag {
	char raw_flags;
	struct {
		char core_trace:1;
		char loader_firmware:1;
		char sdl:1;
		char threaded:1;
	};
}csx_option_t;

/* **** */

#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

/* **** */

#include "csx_mmio.h"
#include "csx_nnd_flash.h"
#include "csx_state.h"
#include "csx_statistics.h"
#include "csx_soc_omap.h"
#include "csx_soc.h"

/* **** */

#include "libarmvm/include/libarmvm.h"

/* **** */

#include "libbse/include/action.h"
#include "libbse/include/unused.h"

/* **** */

#ifndef Kb
	#define Kb(_x)						((_x) * 1024)
#endif

#ifndef Mb
	#define Mb(_x)						(Kb(Kb(_x)))
#endif

/* **** */

typedef struct csx_data_tag {
		uint32_t					base;
		void*						data;
		size_t						size;
}csx_data_t;

typedef struct csx_tag {
	libarmvm_ptr						armvm;
//	armvm_trace_t					armvm_trace;

	csx_mmio_ptr					mmio;
	csx_nnd_ptr						nnd;
	csx_soc_ptr						soc;
	csx_statistics_ptr				statistics;

	csx_state_t						volatile state;

	csx_data_t						x0x10000000;
	csx_data_t						loader;
	csx_data_t						firmware;

	uint8_t							(*sdram)[CSX_SDRAM_ALLOC];

	pthread_t thread;

	csx_option_t					option;
#define OPTION(_) (csx->option._)
}csx_t;

/* **** */

#include "config.h"

csx_ptr csx(void);
int csx_action(int err, csx_ref csx, action_ref action);

__attribute__((warn_unused_result))
csx_ptr csx_alloc(csx_href h2csx);

/* **** */

#ifndef pARMVM
	#define pARMVM csx->armvm
#endif

#ifndef CYCLE
	#define CYCLE libarmvm_cycle(pARMVM)
#endif

#ifndef ICOUNT
	#define ICOUNT libarmvm_icount(pARMVM)
#endif
