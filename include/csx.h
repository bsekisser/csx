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

#include <capstone/capstone.h>

/* **** */

#include "csx_cache.h"
#include "csx_coprocessor.h"
#include "csx_mem.h"
#include "csx_mmio.h"
#include "csx_nnd_flash.h"
#include "csx_state.h"
#include "csx_statistics.h"
#include "csx_soc_exception.h"
#include "csx_soc_omap.h"
#include "csx_soc.h"

/* **** */

#include "callback_qlist.h"
#include "unused.h"

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
	csx_cache_p						cache;
	csx_coprocessor_p				cp;
	csx_mem_p						mem;
	csx_mmio_p						mmio;
	csx_nnd_p						nnd;
	csx_soc_p						soc;
	csx_statistics_p				statistics;
	csx_soc_exception_p				cxu;

	uint64_t						cycle;
	uint64_t						insns;
	csx_state_t						state;

	uint32_t						cr[16 * 16 * 7];
#define _vCR(_x)					vCR(_x)
#define vCR(_x)						csx->cr[_x]

	csh								cs_handle;

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
uint32_t csx_read(csx_p csx, uint32_t ppa, size_t size);
void csx_reset(csx_p csx);
void csx_write(csx_p csx, uint32_t ppa, size_t size, uint32_t write);

