#pragma once

/* **** forward declarations */

typedef struct soc_omap_watchdog_tag** soc_omap_watchdog_hptr;
typedef soc_omap_watchdog_hptr const soc_omap_watchdog_href;

typedef struct soc_omap_watchdog_tag* soc_omap_watchdog_ptr;
typedef soc_omap_watchdog_ptr const soc_omap_watchdog_ref;

/* **** csx includes */

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */

#include "git/libbse/include/action.h"

/* **** system includes */
/* **** */

/* **** */

extern action_list_t soc_omap_watchdog_action_list;

soc_omap_watchdog_ptr soc_omap_watchdog_alloc(soc_omap_watchdog_href h2sow);
