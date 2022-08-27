#pragma once

/* **** */

typedef struct soc_mmio_mpu_ihr_t** soc_mmio_mpu_ihr_h;
typedef struct soc_mmio_mpu_ihr_t* soc_mmio_mpu_ihr_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_mpu_ihr_t {
	csx_p			csx;
	soc_mmio_p		mmio;
}soc_mmio_mpu_ihr_t;

int soc_mmio_mpu_ihr_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_ihr_h h2ihr);
