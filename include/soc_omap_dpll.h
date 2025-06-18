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

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_dpll_action_list;

soc_omap_dpll_ptr soc_omap_dpll_alloc(soc_omap_dpll_href h2dpll);
