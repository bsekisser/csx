#pragma once

// TODO: transition soc to csx_soc

//typedef struct csx_t* csx_p;
typedef struct csx_soc_t** csx_soc_h;
typedef struct csx_soc_t* csx_soc_p;

/* **** */

#include "callback_qlist.h"

/* **** */

#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

// TODO: soc_t from soc_omap_5912.h

typedef struct csx_soc_t {
	// TODO: sram
	// TODO: mmio modules

	csx_p csx;
	
	uint8_t brom[SOC_BROM_ALLOC];
	uint8_t sram[SOC_SRAM_ALLOC]; /* aka framebuffer */
	
	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atexit;

	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atreset;
}csx_soc_t;

void csx_soc_callback_atexit(csx_soc_p soc, callback_qlist_elem_p cble, callback_fn fn, void* param);
void csx_soc_callback_atreset(csx_soc_p soc, callback_qlist_elem_p cble, callback_fn fn, void* param);

csx_soc_p csx_soc_alloc(csx_p csx, csx_soc_h h2soc);
void csx_soc_init(csx_soc_p soc);
int csx_soc_main(csx_p csx, int core_trace, int loader_firmware);
void csx_soc_reset(csx_p csx);
