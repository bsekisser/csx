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

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_misc_action_list;

soc_omap_misc_ptr soc_omap_misc_alloc(soc_omap_misc_href h2misc);
