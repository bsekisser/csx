#pragma once

/* **** */

typedef struct soc_omap_dpll_t** soc_omap_dpll_h;
typedef struct soc_omap_dpll_t* soc_omap_dpll_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_dpll_p soc_omap_dpll_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_dpll_h h2dpll);
void soc_omap_dpll_init(soc_omap_dpll_p dpll);
