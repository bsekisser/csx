#pragma once

/* **** */

typedef struct soc_mmio_ocp_t** soc_mmio_ocp_h;
typedef struct soc_mmio_ocp_t* soc_mmio_ocp_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_ocp_t {
	csx_p			csx;
	soc_mmio_p		mmio;
}soc_mmio_ocp_t;

int soc_mmio_ocp_init(csx_p csx, soc_mmio_p mmio, soc_mmio_ocp_h h2ocp);
