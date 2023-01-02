#pragma once

/* **** */

typedef struct soc_mmio_timer_t** soc_mmio_timer_h;
typedef struct soc_mmio_timer_t* soc_mmio_timer_p;

typedef struct soc_mmio_timer_unit_t* soc_mmio_timer_unit_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_timer_unit_t {
	csx_p				csx;
	soc_mmio_timer_p	timer;

	uint64_t			base;
	
	uint32_t			count;
	uint32_t			ppa_base;
}soc_mmio_timer_unit_t;

typedef struct soc_mmio_timer_t {
	csx_p					csx;
	soc_mmio_p				mmio;
	soc_mmio_peripheral_p	mp[3];

	soc_mmio_timer_unit_t	unit[3];
	
	uint32_t				ppa_base;
}soc_mmio_timer_t;

int soc_mmio_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_timer_h h2t);
