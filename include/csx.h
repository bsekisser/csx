#pragma once

/* **** */

typedef struct csx_t* csx_p;
typedef struct csx_t** csx_h;

typedef struct csx_data_t* csx_data_p;

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

typedef struct csx_data_t {
		uint32_t					base;
		void*						data;
		size_t						size;
}csx_data_t;

typedef struct csx_t {
	armvm_p							armvm;
	armvm_trace_t					armvm_trace;

	csx_cache_p						cache;
	csx_mmio_p						mmio;
	csx_nnd_p						nnd;
	csx_soc_p						soc;
	csx_statistics_p				statistics;

	csx_state_t						state;

	csx_data_t						loader;
	csx_data_t						firmware;

	uint8_t							sdram[CSX_SDRAM_ALLOC];

	callback_qlist_t				atexit_list;
	callback_qlist_t				atreset_list;
}csx_t;

/* **** */

#include "config.h"

csx_p csx_alloc(void);
void csx_atexit(csx_h h2csx);
void csx_callback_atexit(csx_p csx, callback_qlist_elem_p cble, callback_fn fn, void* param);
void csx_callback_atreset(csx_p csx, callback_qlist_elem_p cble, callback_fn fn, void* param);
csx_p csx_init(csx_p csx);
void csx_reset(csx_p csx);

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
