#pragma once

/* **** */

typedef struct soc_omap_mpu_ihr_tag** soc_omap_mpu_ihr_hptr;
typedef soc_omap_mpu_ihr_hptr const soc_omap_mpu_ihr_href;

typedef struct soc_omap_mpu_ihr_tag* soc_omap_mpu_ihr_ptr;
typedef soc_omap_mpu_ihr_ptr const soc_omap_mpu_ihr_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_mpu_ihr_action_list;

soc_omap_mpu_ihr_ptr soc_omap_mpu_ihr_alloc(soc_omap_mpu_ihr_href h2ihr);
