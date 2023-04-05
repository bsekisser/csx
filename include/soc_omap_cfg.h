#pragma once

/* **** */

typedef struct soc_omap_cfg_t** soc_omap_cfg_h;
typedef struct soc_omap_cfg_t* soc_omap_cfg_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

int soc_omap_cfg_init(csx_p csx, csx_mmio_p mmio, soc_omap_cfg_h h2cfg);