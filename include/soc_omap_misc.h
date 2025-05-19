#pragma once

/* **** */

typedef struct soc_omap_misc_tag** soc_omap_misc_hptr;
typedef soc_omap_misc_hptr const soc_omap_misc_href;

typedef struct soc_omap_misc_tag* soc_omap_misc_ptr;
typedef soc_omap_misc_ptr const soc_omap_misc_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_misc_ptr soc_omap_misc_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_misc_href h2misc);
void soc_omap_misc_init(soc_omap_misc_ref misc);
