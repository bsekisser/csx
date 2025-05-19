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

soc_omap_cfg_ptr soc_omap_cfg_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_cfg_href h2cfg);
void soc_omap_cfg_init(soc_omap_cfg_ref cfg);
