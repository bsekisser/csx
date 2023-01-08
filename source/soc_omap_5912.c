/* **** module includes */

#include "soc_omap_timer.h"

/* **** project includes */

#include "soc_omap_5912.h"
#include "soc.h"

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */

#include "err_test.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

int soc_omap5912_init(csx_p csx, soc_h h2soc)
{
	int err = 0;

	soc_p soc = calloc(1, sizeof(soc_t));
	ERR_NULL(soc);

	*h2soc = soc;
	soc->csx = csx;

	/* **** */

	for(int i = 1; i <= 3; i++)
		ERR(err = soc_omap_timer_init(csx, &soc->timer[i], i));
//  soc_omap_watchdog_init(csx, &soc->watchdog);

	return(err);
}
