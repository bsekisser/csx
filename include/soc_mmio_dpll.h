#pragma once

typedef struct soc_mmio_dpll_t** soc_mmio_dpll_h;
typedef struct soc_mmio_dpll_t* soc_mmio_dpll_p;

/* **** */

#include "csx.h"

/* **** */

#include "callback_list.h"

/* **** */

typedef struct soc_mmio_dpll_t {
	csx_p			csx;
	soc_mmio_p		mmio;
}soc_mmio_dpll_t;

int soc_mmio_dpll_init(csx_p csx, soc_mmio_p mmio, soc_mmio_dpll_h h2dpll);
