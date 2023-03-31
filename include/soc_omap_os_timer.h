#pragma once

/* **** */

typedef struct soc_omap_os_timer_t** soc_omap_os_timer_h;
typedef struct soc_omap_os_timer_t* soc_omap_os_timer_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

int soc_omap_os_timer_init(csx_p csx, csx_mmio_p mmio, soc_omap_os_timer_h h2ost);
