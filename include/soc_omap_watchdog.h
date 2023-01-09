#pragma once

/* **** forward declarations */

typedef struct soc_omap_watchdog_t** soc_omap_watchdog_h;
typedef struct soc_omap_watchdog_t* soc_omap_watchdog_p;

/* **** csx includes */

#include "csx_mmio_reg_t.h"
#include "csx.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

typedef struct soc_omap_watchdog_t {
	csx_p					csx;
}soc_omap_watchdog_t;

/* **** */

int soc_omap_watchdog_init(csx_p csx, soc_omap_watchdog_h sow);
