#pragma once

/* **** */

typedef struct soc_omap_mpu_gpio_tag** soc_omap_mpu_gpio_hptr;
typedef soc_omap_mpu_gpio_hptr const soc_omap_mpu_gpio_href;

typedef struct soc_omap_mpu_gpio_tag* soc_omap_mpu_gpio_ptr;
typedef soc_omap_mpu_gpio_ptr const soc_omap_mpu_gpio_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_mpu_gpio_ptr soc_omap_mpu_gpio_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_gpio_href h2gpio);
void soc_omap_mpu_gpio_init(soc_omap_mpu_gpio_ref gpio);
