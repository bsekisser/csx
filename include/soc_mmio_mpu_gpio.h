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
	
	uint8_t					data[4][256];
}soc_mmio_mpu_gpio_t;

int soc_mmio_mpu_gpio_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_gpio_h h2gpio);
//uint32_t soc_mmio_mpu_gpio_read(soc_mmio_mpu_gpio_p gpio, uint32_t address, uint8_t size);
//void soc_mmio_mpu_gpio_reset(soc_mmio_mpu_gpio_p gpio);
//void soc_mmio_mpu_gpio_write(soc_mmio_mpu_gpio_p gpio, uint32_t address, uint32_t value, uint8_t size);
