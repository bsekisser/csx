#pragma once

/* **** forward declarations/definitions */

typedef struct soc_omap_dma_t** soc_omap_dma_h;
typedef struct soc_omap_dma_t* soc_omap_dma_p;

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_dma_p soc_omap_dma_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_dma_h h2dma);
void soc_omap_dma_init(soc_omap_dma_p dma);
