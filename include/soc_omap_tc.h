#pragma once

/* **** */

typedef struct soc_omap_tc_tag** soc_omap_tc_hptr;
typedef soc_omap_tc_hptr soc_omap_tc_href;

typedef struct soc_omap_tc_tag* soc_omap_tc_ptr;
typedef soc_omap_tc_ptr soc_omap_tc_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_tc_action_list;

soc_omap_tc_ptr soc_omap_tc_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_tc_href h2tc);
