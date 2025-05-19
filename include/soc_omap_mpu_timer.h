#pragma once

/* **** forward declarations */

typedef struct soc_omap_mpu_timer_tag** soc_omap_mpu_timer_hptr;
typedef soc_omap_mpu_timer_hptr const soc_omap_mpu_timer_href;

typedef struct soc_omap_mpu_timer_tag* soc_omap_mpu_timer_ptr;
typedef soc_omap_mpu_timer_ptr const soc_omap_mpu_timer_ref;

/* **** project includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */
/* **** system includes */
/* **** */
/* **** */

soc_omap_mpu_timer_ptr soc_omap_mpu_timer_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_timer_href h2t);
void soc_omap_mpu_timer_init(soc_omap_mpu_timer_ref t);
