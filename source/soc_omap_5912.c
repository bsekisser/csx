/* **** module includes */

#include "soc_omap_timer.h"

/* **** project includes */

#include "soc_omap_5912.h"
#include "soc.h"

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

void soc_omap5912_init(csx_p csx, soc_p soc) {
    for(int i = 0; i < 3; i++)
        soc_omap_timer_init(csx, &soc->timer[i]);
//  soc_omap_watchdog_init(csx, &soc->watchdog);
}
