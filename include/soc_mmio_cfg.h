#pragma once

/* **** */

typedef struct soc_mmio_cfg_t** soc_mmio_cfg_h;
typedef struct soc_mmio_cfg_t* soc_mmio_cfg_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_cfg_t {
	csx_p			csx;
	soc_mmio_p		mmio;
}soc_mmio_cfg_t;

int soc_mmio_cfg_init(csx_p csx, soc_mmio_p mmio, soc_mmio_cfg_h cfg);
