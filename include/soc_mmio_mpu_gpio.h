#pragma once

/* **** */

typedef struct soc_mmio_mpu_gpio_t** soc_mmio_mpu_gpio_h;
typedef struct soc_mmio_mpu_gpio_t* soc_mmio_mpu_gpio_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_mpu_gpio_t {
	csx_p					csx;
	soc_mmio_p				mmio;
}soc_mmio_mpu_gpio_t;

int soc_mmio_mpu_gpio_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_gpio_h h2gpio);
