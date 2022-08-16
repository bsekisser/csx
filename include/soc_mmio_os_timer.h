#pragma once

/* **** */

typedef struct soc_mmio_os_timer_t** soc_mmio_os_timer_h;
typedef struct soc_mmio_os_timer_t* soc_mmio_os_timer_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_os_timer_t {
	csx_p			csx;
	soc_mmio_p		mmio;
	
	uint64_t		base;
}soc_mmio_os_timer_t;

int soc_mmio_os_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_os_timer_h h2ost);
