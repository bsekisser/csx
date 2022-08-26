#include "soc_mmio_watchdog.h"

#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define _WDT(_x)		(CSX_MMIO_WATCHDOG_BASE | (_x))

#define _WDT_TIMER(_x)	(CSX_MMIO_TIMER_WDT_BASE | (_x))

//#define WWPS					_WDT(0x034)
//#define WSPR					_WDT(0x048)

//#define MPU_WDT_TIMER_MODE	_WDT_TIMER(0x008)

#define MMIO_LIST_0 \
	MMIO_TRACE_LIST_HEAD(watchdog) \
	MMIO(0xfffe, 0xb034, 0x0000, 0x0000, 32, MEM_RW, WWPS) \
	MMIO(0xfffe, 0xb048, 0x0000, 0x0000, 32, MEM_RW, WSPR) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST_1 \
	MMIO_TRACE_LIST_HEAD(timer) \
	MMIO(0xfffe, 0xc808, 0x0000, 0x8000, 32, MEM_RW, MPU_WDT_TIMER_MODE) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST \
	MMIO_LIST_0 \
	MMIO_LIST_1

#include "soc_mmio_trace.h"

#include "soc_mmio_ea_trace_enum.h"
MMIO_ENUM_LIST

#include "soc_mmio_ea_trace_list.h"
MMIO_TRACE_LIST

static soc_mmio_peripheral_t watchdog_peripheral[2] = {
	{
		.base = CSX_MMIO_WATCHDOG_BASE,
		.trace_list = trace_list_watchdog,
	}, {
		.base = CSX_MMIO_TIMER_WDT_BASE,
		.trace_list = trace_list_timer,
	},
};

int soc_mmio_watchdog_init(csx_p csx, soc_mmio_p mmio, soc_mmio_watchdog_h h2wdt)
{
	soc_mmio_watchdog_p wdt = calloc(1, sizeof(soc_mmio_watchdog_t));
	
	ERR_NULL(wdt);
	if(!wdt)
		return(-1);

	wdt->csx = csx;
	wdt->mmio = mmio;
	
	*h2wdt = wdt;
	
	soc_mmio_peripheral(mmio, &watchdog_peripheral[0], wdt);
	soc_mmio_peripheral(mmio, &watchdog_peripheral[1], wdt);
	
	return(0);
}
