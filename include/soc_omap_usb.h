#pragma once

/* **** forward declarations/definitions */

typedef struct soc_omap_usb_tag** soc_omap_usb_hptr;
typedef soc_omap_usb_hptr const soc_omap_usb_href;

typedef struct soc_omap_usb_tag* soc_omap_usb_ptr;
typedef soc_omap_usb_ptr const soc_omap_usb_ref;

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

#include "git/libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_usb_action_list;

soc_omap_usb_ptr soc_omap_usb_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_usb_href h2usb);
