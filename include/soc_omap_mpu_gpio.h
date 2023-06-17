#pragma once

/* **** */

typedef struct soc_omap_mpu_gpio_t** soc_omap_mpu_gpio_h;
typedef struct soc_omap_mpu_gpio_t* soc_omap_mpu_gpio_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_mpu_gpio_p soc_omap_mpu_gpio_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_gpio_h h2gpio);
void soc_omap_mpu_gpio_init(soc_omap_mpu_gpio_p gpio);
