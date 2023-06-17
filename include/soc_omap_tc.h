#pragma once

/* **** */

typedef struct soc_omap_tc_t** soc_omap_tc_h;
typedef struct soc_omap_tc_t* soc_omap_tc_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_tc_p soc_omap_tc_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_tc_h h2tc);
void soc_omap_tc_init(soc_omap_tc_p tc);
