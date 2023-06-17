#pragma once

/* **** forward declarations/definitions */

typedef struct soc_omap_usb_t** soc_omap_usb_h;
typedef struct soc_omap_usb_t* soc_omap_usb_p;

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_usb_p soc_omap_usb_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_usb_h h2usb);
void soc_omap_usb_init(soc_omap_usb_p usb);
