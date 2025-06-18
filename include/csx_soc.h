#pragma once

typedef struct csx_soc_tag** csx_soc_hptr;
typedef csx_soc_hptr const csx_soc_href;

typedef struct csx_soc_tag* csx_soc_ptr;
typedef csx_soc_ptr const csx_soc_ref;

/* **** */

#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

typedef struct csx_soc_tag {
	uint8_t (*brom)[SOC_BROM_ALLOC];
	uint8_t (*sram)[SOC_SRAM_ALLOC]; /* aka framebuffer */

	csx_ptr csx;
}csx_soc_t;

extern action_list_t csx_soc_action_list;

csx_soc_ptr csx_soc(void);
csx_soc_ptr csx_soc_alloc(csx_soc_href h2soc);
int csx_soc_main(csx_ref csx, const int core_trace, const int loader_firmware);
