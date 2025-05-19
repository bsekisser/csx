#pragma once

/* **** forward declarations/definitions */

typedef struct soc_omap_dma_tag** soc_omap_dma_hptr;
typedef soc_omap_dma_hptr const soc_omap_dma_href;

typedef struct soc_omap_dma_tag* soc_omap_dma_ptr;
typedef soc_omap_dma_ptr const soc_omap_dma_ref;

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_dma_ptr soc_omap_dma_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_dma_href h2dma);
void soc_omap_dma_init(soc_omap_dma_ref dma);
