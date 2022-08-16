#pragma once

/* **** */

typedef struct soc_mmio_watchdog_t** soc_mmio_watchdog_h;
typedef struct soc_mmio_watchdog_t* soc_mmio_watchdog_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_watchdog_t {
	csx_p			csx;
	soc_mmio_p		mmio;
}soc_mmio_watchdog_t;

int soc_mmio_watchdog_init(csx_p csx, soc_mmio_p mmio, soc_mmio_watchdog_h wdt);
