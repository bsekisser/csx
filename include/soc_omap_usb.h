#pragma once

/* **** forward declarations/definitions */

typedef struct soc_omap_usb_t** soc_omap_usb_h;
typedef struct soc_omap_usb_t* soc_omap_usb_p;

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

int soc_omap_usb_init(csx_p csx, csx_mmio_p mmio, soc_omap_usb_h h2usb);
