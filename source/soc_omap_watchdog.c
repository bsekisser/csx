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

MMIO_ESAC(MPU_WDT, TIMER_MODE)



/* **** */

static void _soc_omap_wdt_reset(void* param)
{
	soc_omap_watchdog_p sow = param;
	
	WDT_TIMER_CNTL_SET(sow, 0x00000e02);
	WDT_TIMER_LOAD_SET(sow, 0x0000ffff);
	WDT_TIMER_MODE_SET(sow, 0x00008000);
}

static uint32_t _soc_omap_wdt_read(void* param, uint32_t mpa, uint8_t size)
{
	soc_omap_watchdog_p sow = param;
	
	switch(_MODULE_DATA_OFFSET(mpa)) {
		case _MPU_WDT_TIMER_READ:
			_wdt_update(sow);
		case _MPU_WDT_TIMER_CNTL:
		case _MPU_WDT_TIMER_MODE:
			break;
	}
}

/* **** */

int soc_omap_watchdog_init(csx_p csx, soc_omap_watchdog_h h2sow)
{
	soc_omap_watchdog_p sow = calloc(1, sizeof(soc_omap_watchdog_t));
	ERR_NULL(sow);
	
	sow->csx = csx;
	*h2sow = sow;
	
	/* **** */
	
	csx_mmio_register_read(csx, SOC_MMIO_WDT_BASE, _soc_omap_wdt_read, sow);
	csx_mmio_register_write(csx, SOC_MMIO_WDT_BASE, _soc_omap_wdt_write, sow);
	
	csx_mmio_register_reset(csx, _soc_omap_watchdog_reset, sow);
	csx_mmio_register_reset(csx, _soc_omap_wdt_reset, sow);
	
	/* **** */
	
	return(0);
}
