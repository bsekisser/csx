#pragma once

/* **** */

typedef struct soc_mmio_ocp_t** soc_mmio_ocp_h;
typedef struct soc_mmio_ocp_t* soc_mmio_ocp_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_ocp_t {
	csx_p			csx;
	soc_mmio_p		mmio;
	
	struct {
		uint32_t	adv_config;
		uint32_t	config;
	}emifs[4];
}soc_mmio_ocp_t;

int soc_mmio_ocp_init(csx_p csx, soc_mmio_p mmio, soc_mmio_ocp_h h2ocp);
//uint32_t soc_mmio_ocp_read(soc_mmio_ocp_p ocp, uint32_t address, uint8_t size);
//void soc_mmio_ocp_reset(soc_mmio_ocp_p ocp);
//void soc_mmio_ocp_write(soc_mmio_ocp_p ocp, uint32_t address, uint32_t value, uint8_t size);
