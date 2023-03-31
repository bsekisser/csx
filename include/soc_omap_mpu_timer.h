#pragma once

/* **** forward declarations */

typedef struct soc_omap_mpu_timer_t** soc_omap_mpu_timer_h;
typedef struct soc_omap_mpu_timer_t* soc_omap_mpu_timer_p;

/* **** project includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */
/* **** system includes */
/* **** */
/* **** */

int soc_omap_mpu_timer_init(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_timer_h timer);
