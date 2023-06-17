#pragma once

/* **** forward declarations */

typedef struct soc_omap_watchdog_t** soc_omap_watchdog_h;
typedef struct soc_omap_watchdog_t* soc_omap_watchdog_p;

/* **** csx includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */
/* **** system includes */
/* **** */

/* **** */

soc_omap_watchdog_p soc_omap_watchdog_alloc(csx_p csx,
	csx_mmio_p mmio, soc_omap_watchdog_h h2sow);
void soc_omap_watchdog_init(soc_omap_watchdog_p sow);
