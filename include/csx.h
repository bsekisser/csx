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

#include "soc_core.h"
//#include "soc_core_coprocessor.h"
#include "soc_mmu.h"
#include "csx_nnd_flash.h"
#include "soc_tlb.h"
#include "soc.h" // TODO: move soc to csx_soc

/* **** */

#include "csx_mem.h"
#include "csx_mmio.h"
#include "csx_state.h"
#include "csx_soc_omap.h"

/* **** */

#include "callback_list.h"
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
	csx_mem_p						mem;
	csx_mmio_p						mmio;
	csx_soc_p						soc;

	soc_core_p						core;
//	soc_coprocessor_p				cp;
	soc_mmu_p						mmu;
	csx_nnd_p						nnd;
	soc_tlb_p						tlb;

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

	callback_list_t					atexit_list;
	callback_list_t					atreset_list;
}csx_t;

/* **** */

#include "config.h"

void csx_atexit(csx_h h2csx);
void csx_callback_atexit(csx_p csx, callback_fn fn, void* param);
void csx_callback_atreset(csx_p csx, callback_fn fn, void* param);
csx_p csx_init(void);
uint32_t csx_read(csx_p csx, uint32_t ppa, size_t size);
void csx_reset(csx_p csx);
void csx_write(csx_p csx, uint32_t ppa, size_t size, uint32_t write);

