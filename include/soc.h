#pragma once

// TODO: transition soc to csx_soc

//typedef struct csx_t* csx_p;
typedef struct csx_soc_t** csx_soc_h;
typedef struct csx_soc_t* csx_soc_p;

/* **** */

#include "callback_list.h"

/* **** */

#include "csx.h"

/* **** */

// TODO: soc_t from soc_omap_5912.h

enum {
	CSX_SRAM_BASE = 0x20000000UL,
//	CSX_SRAM_END = 0x2003e7ffUL, /* TODO: actual on chip sram listed as 250Kb */
	CSX_SRAM_END = 0x2003efffUL,
	CSX_SRAM_ALLOC,
};

typedef struct csx_soc_t {
	// TODO: sram
	// TODO: mmio modules

	csx_p csx;
	
	uint8_t sram[CSX_SRAM_ALLOC]; /* aka framebuffer */
	
	callback_list_t atexit_list;
	callback_list_t atreset_list;
}csx_soc_t;

void csx_soc_callback_atexit(csx_soc_p soc, callback_fn fn, void* param);
void csx_soc_callback_atreset(csx_soc_p soc, callback_fn fn, void* param);

int csx_soc_init(csx_p csx, csx_soc_h h2soc);
int csx_soc_main(csx_p csx, int core_trace, int loader_firmware);
void csx_soc_reset(csx_p csx);
