#pragma once

/* **** */

typedef struct soc_omap_misc_t** soc_omap_misc_h;
typedef struct soc_omap_misc_t* soc_omap_misc_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_misc_p soc_omap_misc_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_misc_h h2misc);
void soc_omap_misc_init(soc_omap_misc_p misc);
