#pragma once

/* **** */

typedef struct soc_mmio_cfg_t** soc_mmio_cfg_h;
typedef struct soc_mmio_cfg_t* soc_mmio_cfg_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_cfg_t {
	csx_p			csx;
	soc_mmio_p		mmio;

	uint8_t			data[0x1ff];
}soc_mmio_cfg_t;

int soc_mmio_cfg_init(csx_p csx, soc_mmio_p mmio, soc_mmio_cfg_h cfg);
//uint32_t soc_mmio_cfg_read(soc_mmio_cfg_p cfg, uint32_t address, uint8_t size);
//void soc_mmio_cfg_reset(soc_mmio_cfg_p cfg);
//void soc_mmio_cfg_write(soc_mmio_cfg_p cfg, uint32_t address, uint32_t value, uint8_t size);
