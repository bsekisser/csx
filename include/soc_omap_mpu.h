#pragma once

/* **** */

typedef struct soc_omap_mpu_tag** soc_omap_mpu_hptr;
typedef soc_omap_mpu_hptr const soc_omap_mpu_href;

typedef struct soc_omap_mpu_tag* soc_omap_mpu_ptr;
typedef soc_omap_mpu_ptr const soc_omap_mpu_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_mpu_ptr soc_omap_mpu_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_href h2mpu);
void soc_omap_mpu_init(soc_omap_mpu_ref mpu);
