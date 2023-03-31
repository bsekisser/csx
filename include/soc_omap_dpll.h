#pragma once

/* **** */

typedef struct soc_omap_dpll_t** soc_omap_dpll_h;
typedef struct soc_omap_dpll_t* soc_omap_dpll_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

int soc_omap_dpll_init(csx_p csx, csx_mmio_p mmio, soc_omap_dpll_h h2dpll);
