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

#ifndef uint
	typedef unsigned int uint;
#endif

/* **** */

#include "soc_core.h"
//#include "soc_core_coprocessor.h"
#include "soc_mmu.h"
#include "soc_nnd_flash.h"
#include "soc_tlb.h"
#include "soc.h" // TODO: move soc to csx_soc

/* **** */

#include "csx_mem.h"
#include "csx_mmio.h"
#include "csx_state.h"

/* **** */

#include "callback_list.h"
#include "unused.h"

/* **** */

#define CSX_SDRAM_BASE			0x10000000
#define CSX_SDRAM_SIZE			Mb(16)
#define CSX_SDRAM_STOP			((CSX_SDRAM_BASE + CSX_SDRAM_SIZE) - 1)

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
	soc_nnd_p						nnd;
	soc_tlb_p						tlb;

	uint64_t						cycle;
	uint64_t						insns;
	csx_state_t						state;

	uint32_t						cr[16 * 16 * 7];
#define _vCR(_x)					vCR(_x)
#define vCR(_x)						csx->cr[_x]

	csh								cs_handle;

	csx_data_p						cdp;
	csx_data_t						loader;
	csx_data_t						firmware;

	uint8_t							sdram[CSX_SDRAM_SIZE];

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

