#pragma once

/* **** */

typedef struct soc_omap_mpu_ihr_t** soc_omap_mpu_ihr_h;
typedef struct soc_omap_mpu_ihr_t* soc_omap_mpu_ihr_p;

/* **** */

#include "csx.h"

/* **** */

int soc_omap_mpu_ihr_init(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_ihr_h h2ihr);
