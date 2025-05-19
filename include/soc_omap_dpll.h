#pragma once

/* **** */

typedef struct soc_omap_dpll_tag** soc_omap_dpll_hptr;
typedef soc_omap_dpll_hptr const soc_omap_dpll_href;

typedef struct soc_omap_dpll_tag* soc_omap_dpll_ptr;
typedef soc_omap_dpll_ptr const soc_omap_dpll_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_dpll_ptr soc_omap_dpll_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_dpll_href h2dpll);
void soc_omap_dpll_init(soc_omap_dpll_ref dpll);
