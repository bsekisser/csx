#pragma once

/* **** */

typedef struct soc_mmio_mpu_t** soc_mmio_mpu_h;
typedef struct soc_mmio_mpu_t* soc_mmio_mpu_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_mpu_t {
	csx_p			csx;
	soc_mmio_p		mmio;
}soc_mmio_mpu_t;

int soc_mmio_mpu_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_h h2mpu);
