#pragma once

/* **** */

typedef struct soc_omap_mpu_ihr_t** soc_omap_mpu_ihr_h;
typedef struct soc_omap_mpu_ihr_t* soc_omap_mpu_ihr_p;

/* **** */

#include "csx.h"

/* **** */

soc_omap_mpu_ihr_p soc_omap_mpu_ihr_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_ihr_h h2ihr);
void soc_omap_mpu_ihr_init(soc_omap_mpu_ihr_p ihr);
