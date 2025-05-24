#pragma once

typedef struct soc_omap_mpu_mmc_tag** soc_omap_mpu_mmc_hptr;
typedef soc_omap_mpu_mmc_hptr const soc_omap_mpu_mmc_href;

typedef struct soc_omap_mpu_mmc_tag* soc_omap_mpu_mmc_ptr;
typedef soc_omap_mpu_mmc_ptr const soc_omap_mpu_mmc_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_mpu_mmc_action_list;

soc_omap_mpu_mmc_ptr soc_omap_mpu_mmc_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_mmc_href h2mmc);
