#pragma once

/* **** */

typedef struct soc_omap_mpu_ihr_tag** soc_omap_mpu_ihr_hptr;
typedef soc_omap_mpu_ihr_hptr const soc_omap_mpu_ihr_href;

typedef struct soc_omap_mpu_ihr_tag* soc_omap_mpu_ihr_ptr;
typedef soc_omap_mpu_ihr_ptr const soc_omap_mpu_ihr_ref;

/* **** */

#include "csx.h"

/* **** */

soc_omap_mpu_ihr_ptr soc_omap_mpu_ihr_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_ihr_href h2ihr);
void soc_omap_mpu_ihr_init(soc_omap_mpu_ihr_ref ihr);
