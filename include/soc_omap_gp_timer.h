#pragma once

/* **** */

typedef struct soc_omap_gp_timer_tag** soc_omap_gp_timer_hptr;
typedef soc_omap_gp_timer_hptr const soc_omap_gp_timer_href;

typedef struct soc_omap_gp_timer_tag* soc_omap_gp_timer_ptr;
typedef soc_omap_gp_timer_ptr const soc_omap_gp_timer_ref;

/* **** */

#include "csx.h"

/* **** */

soc_omap_gp_timer_ptr soc_omap_gp_timer_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_gp_timer_href h2gpt);
void soc_omap_gp_timer_init(soc_omap_gp_timer_ref gpt);
