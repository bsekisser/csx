/* **** module includes */

#include "soc_omap_timer.h"

/* **** project includes */

#include "soc_omap_5912.h"
#include "soc.h"

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */

#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

static int _soc_omap5912_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	handle_free(param);
	return(0);
}

int soc_omap5912_init(csx_p csx, soc_h h2soc)
{
	assert(0 != csx);
	assert(0 != h2soc);

	if(_trace_init) {
		LOG();
	}

	int err = 0;

	soc_p soc = HANDLE_CALLOC(h2soc, 1, sizeof(soc_t));
	ERR_NULL(soc);

	soc->csx = csx;

	csx_callback_atexit(csx, _soc_omap5912_atexit, h2soc);

	/* **** */

	for(int i = 1; i <= 3; i++)
		ERR(err = soc_omap_timer_init(csx, &soc->timer[i - 1], i));
	soc_omap_watchdog_init(csx, &soc->watchdog);

	return(err);
}
