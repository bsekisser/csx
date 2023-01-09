#include "soc_omap_watchdog.h"

/* **** */

#include "csx_mmio_trace.h"

/* **** local includes */

#include "err_test.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */


#define MMIO_LIST \
	MMIO_TRACE(0xfffe, 0xb034, 32, Rw, 0x0000, 0x0000, WWPS) \
	MMIO_TRACE(0xfffe, 0xb048, 32, RW, 0x0000, 0x0000, WSPR) \
	MMIO_TRACE(0xfffe, 0xc808, 16, RW, 0x0000, 0x8000, MPU_WDT_TIMER_MODE)
	
/* **** */

#define MMIO_TRACE MMIO_TRACE_T
csx_mmio_trace_t trace_list[] = {
	MMIO_LIST
	{ 0, },
};
#undef MMIO_TRACE

/* **** */

int soc_omap_watchdog_init(csx_p csx, soc_omap_watchdog_h h2sow)
{
	soc_omap_watchdog_p sow = calloc(1, sizeof(soc_omap_watchdog_t));
	ERR_NULL(sow);
	
	sow->csx = csx;
	*h2sow = sow;
	
	/* **** */
	
	csx_mmio_register_trace_list(csx, trace_list);
	
	/* **** */
	
	return(0);
}
