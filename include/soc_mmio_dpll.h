#pragma once

typedef struct soc_mmio_dpll_t** soc_mmio_dpll_h;
typedef struct soc_mmio_dpll_t* soc_mmio_dpll_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_dpll_t {
	csx_p			csx;
	soc_mmio_p		mmio;

	uint32_t		ctl_reg[1];
}soc_mmio_dpll_t;

int soc_mmio_dpll_init(csx_p csx, soc_mmio_p mmio, soc_mmio_dpll_h h2dpll);
//uint32_t soc_mmio_dpll_read(soc_mmio_dpll_p dpll, uint32_t address, uint8_t size);
//void soc_mmio_dpll_reset(soc_mmio_dpll_p dpll);
//void soc_mmio_dpll_write(soc_mmio_dpll_p dpll, uint32_t address, uint32_t value, uint8_t size);
