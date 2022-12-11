#pragma once

typedef struct soc_mmio_mpu_mmc_t** soc_mmio_mpu_mmc_h;
typedef struct soc_mmio_mpu_mmc_t* soc_mmio_mpu_mmc_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_mpu_mmc_t {
	csx_p			csx;
	soc_mmio_p		mmio;
}soc_mmio_mpu_mmc_t;

int soc_mmio_mpu_mmc_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_mmc_h h2mpu_mmc);
