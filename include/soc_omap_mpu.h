#pragma once

/* **** */

typedef struct soc_omap_mpu_tag** soc_omap_mpu_hptr;
typedef soc_omap_mpu_hptr const soc_omap_mpu_href;

typedef struct soc_omap_mpu_tag* soc_omap_mpu_ptr;
typedef soc_omap_mpu_ptr const soc_omap_mpu_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_mpu_action_list;

soc_omap_mpu_ptr soc_omap_mpu_alloc(soc_omap_mpu_href h2mpu);
