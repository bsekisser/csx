#pragma once

/* **** */

typedef struct soc_omap_mpu_gpio_tag** soc_omap_mpu_gpio_hptr;
typedef soc_omap_mpu_gpio_hptr const soc_omap_mpu_gpio_href;

typedef struct soc_omap_mpu_gpio_tag* soc_omap_mpu_gpio_ptr;
typedef soc_omap_mpu_gpio_ptr const soc_omap_mpu_gpio_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_mpu_gpio_action_list;

soc_omap_mpu_gpio_ptr soc_omap_mpu_gpio_alloc(soc_omap_mpu_gpio_href h2gpio);
