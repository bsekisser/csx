#pragma once

/* **** */

typedef struct csx_tag* csx_ptr;
typedef csx_ptr const csx_ref;

typedef struct csx_tag** csx_hptr;
typedef csx_hptr const csx_href;

typedef struct csx_data_tag* csx_data_ptr;
typedef csx_data_ptr const csx_data_ref;

/* **** */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/* **** */

#include "csx_cache.h"
#include "csx_mmio.h"
#include "csx_nnd_flash.h"
#include "csx_state.h"
#include "csx_statistics.h"
#include "csx_soc_omap.h"
#include "csx_soc.h"

/* **** */

#include "libarmvm/include/armvm.h"

/* **** */

#include "libbse/include/callback_qlist.h"
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
	armvm_ptr						armvm;
	armvm_trace_t					armvm_trace;

	csx_cache_ptr					cache;
	csx_mmio_ptr					mmio;
	csx_nnd_ptr						nnd;
	csx_soc_ptr						soc;
	csx_statistics_ptr				statistics;

	csx_state_t						state;

	csx_data_t						x0x10000000;
	csx_data_t						loader;
	csx_data_t						firmware;

	uint8_t							sdram[CSX_SDRAM_ALLOC];

	callback_qlist_t				atexit_list;
	callback_qlist_t				atreset_list;
}csx_t;

/* **** */

#include "config.h"

csx_ptr csx_alloc(void);
void csx_atexit(csx_href h2csx);
void csx_callback_atexit(csx_ref csx, callback_qlist_elem_p const cble, callback_fn const fn, void *const param);
void csx_callback_atreset(csx_ref csx, callback_qlist_elem_p const cble, callback_fn const fn, void *const param);
csx_ptr csx_init(csx_ref csx);
void csx_reset(csx_ref csx);

/* **** */

#ifndef pARMVM
	#define pARMVM csx->armvm
#endif

#ifndef pARMVM_MEM
	#define pARMVM_MEM pARMVM->mem
#endif

#ifndef CYCLE
	#define CYCLE armvm_spr64(pARMVM, ARMVM_SPR64(CYCLE))
#endif

#ifndef ICOUNT
	#define ICOUNT armvm_spr64(pARMVM, ARMVM_SPR64(ICOUNT))
#endif
