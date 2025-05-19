#pragma once

/* **** */

typedef struct soc_omap_os_timer_tag** soc_omap_os_timer_hptr;
typedef soc_omap_os_timer_hptr const soc_omap_os_timer_href;

typedef struct soc_omap_os_timer_tag* soc_omap_os_timer_ptr;
typedef soc_omap_os_timer_ptr const soc_omap_os_timer_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_os_timer_ptr soc_omap_os_timer_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_os_timer_href h2ost);
void soc_omap_os_timer_init(soc_omap_os_timer_ref ost);
