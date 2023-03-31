#pragma once

/* **** */

typedef struct soc_omap_mpu_t** soc_omap_mpu_h;
typedef struct soc_omap_mpu_t* soc_omap_mpu_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

int soc_omap_mpu_init(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_h h2mpu);
