#pragma once

typedef struct soc_omap_mpu_mmc_t** soc_omap_mpu_mmc_h;
typedef struct soc_omap_mpu_mmc_t* soc_omap_mpu_mmc_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_mpu_mmc_p soc_omap_mpu_mmc_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_mmc_h h2mpu_mmc);
void soc_omap_mpu_mmc_init(soc_omap_mpu_mmc_p mmc);
