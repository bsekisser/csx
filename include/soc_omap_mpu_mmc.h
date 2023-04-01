#pragma once

typedef struct soc_omap_mpu_mmc_t** soc_omap_mpu_mmc_h;
typedef struct soc_omap_mpu_mmc_t* soc_omap_mpu_mmc_p;

/* **** */

#include "csx.h"

/* **** */

int soc_omap_mpu_mmc_init(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_mmc_h h2mpu_mmc);
