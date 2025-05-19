#pragma once

typedef struct csx_soc_tag** csx_soc_hptr;
typedef csx_soc_hptr const csx_soc_href;

typedef struct csx_soc_tag* csx_soc_ptr;
typedef csx_soc_ptr const csx_soc_ref;

/* **** */

#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "libbse/include/callback_qlist.h"

/* **** */

typedef struct csx_soc_tag {
	uint8_t brom[SOC_BROM_ALLOC];
	uint8_t sram[SOC_SRAM_ALLOC]; /* aka framebuffer */

	csx_ptr csx;

	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atexit;

	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atreset;
}csx_soc_t;

void csx_soc_callback_atexit(csx_soc_ref soc, callback_qlist_elem_p const cble, callback_fn const fn, void *const param);
void csx_soc_callback_atreset(csx_soc_ref soc, callback_qlist_elem_p const cble, callback_fn const fn, void *const param);

csx_soc_ptr csx_soc_alloc(csx_ref csx, csx_soc_href h2soc);
void csx_soc_init(csx_soc_ref soc);
int csx_soc_main(csx_ref csx, const int core_trace, const int loader_firmware);
void csx_soc_reset(csx_ref csx);
