#pragma once

/* **** */

typedef struct soc_omap_gp_timer_t** soc_omap_gp_timer_h;
typedef struct soc_omap_gp_timer_t* soc_omap_gp_timer_p;

/* **** */

#include "csx.h"

/* **** */

soc_omap_gp_timer_p soc_omap_gp_timer_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_gp_timer_h h2gpt);
void soc_omap_gp_timer_init(soc_omap_gp_timer_p gpt);
