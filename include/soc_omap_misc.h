#pragma once

/* **** */

typedef struct soc_omap_misc_t** soc_omap_misc_h;
typedef struct soc_omap_misc_t* soc_omap_misc_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

int soc_omap_misc_init(csx_p csx, csx_mmio_p mmio, soc_omap_misc_h h2misc);
