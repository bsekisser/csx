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

#include "libbse/include/action.h"

/* **** */

extern action_list_t soc_omap_os_timer_action_list;

soc_omap_os_timer_ptr soc_omap_os_timer_alloc(soc_omap_os_timer_href h2ost);
