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

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_dma_action_list;

soc_omap_dma_ptr soc_omap_dma_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_dma_href h2dma);
