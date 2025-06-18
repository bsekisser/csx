#pragma once

/* **** */

typedef struct soc_omap_cfg_tag** soc_omap_cfg_hptr;
typedef soc_omap_cfg_hptr const soc_omap_cfg_href;

typedef struct soc_omap_cfg_tag* soc_omap_cfg_ptr;
typedef soc_omap_cfg_ptr const soc_omap_cfg_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_cfg_action_list;

soc_omap_cfg_ptr soc_omap_cfg_alloc(soc_omap_cfg_href h2cfg);
