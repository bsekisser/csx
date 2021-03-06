#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_watchdog.h"

#define _WDT(_x)		(CSX_MMIO_WATCHDOG_BASE | (_x))

#define _WDT_TIMER(_x)	(CSX_MMIO_TIMER_WDT_BASE | (_x))

//#define WWPS					_WDT(0x034)
//#define WSPR					_WDT(0x048)

//#define MPU_WDT_TIMER_MODE	_WDT_TIMER(0x008)

#define MMIO_LIST \
	MMIO(0xfffe, 0xb034, 0x0000, 0x0000, 32, MEM_RW, WWPS) \
	MMIO(0xfffe, 0xb048, 0x0000, 0x0000, 32, MEM_RW, WSPR) \
	\
	MMIO(0xfffe, 0xc808, 0x0000, 0x8000, 32, MEM_RW, MPU_WDT_TIMER_MODE)

#include "csx_mmio_trace.h"

static uint32_t csx_mmio_watchdog_read(void* data, uint32_t addr, uint8_t size)
{
	const csx_mmio_watchdog_p wdt = data;
	const csx_p csx = wdt->csx;
	
	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value;
	
	switch(addr)
	{
		case	WWPS:
			value = wdt->wwps;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
	return(value);
}

static void csx_mmio_watchdog_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const csx_mmio_watchdog_p wdt = data;
	const csx_p csx = wdt->csx;
	
	csx_mmio_trace(csx->mmio, trace_list, addr);

	switch(addr)
	{
		case	WSPR:
			wdt->wspr = value;
			break;
		case	MPU_WDT_TIMER_MODE:
			wdt->timer.mode = value;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

static void csx_mmio_watchdog_reset(void* data)
{
	const csx_mmio_watchdog_p wdt = data;

	wdt->wwps = 0;
	wdt->wspr = 0;
	
	wdt->timer.mode = 0x00008000;
}

static csx_mmio_peripheral_t watchdog_peripheral[2] = {
	[0] = {
		.base = CSX_MMIO_WATCHDOG_BASE,

		.reset = csx_mmio_watchdog_reset,

		.read = csx_mmio_watchdog_read,
		.write = csx_mmio_watchdog_write
	},
	[1] = {
		.base = CSX_MMIO_TIMER_WDT_BASE,

//		.reset = csx_mmio_watchdog_reset,

		.read = csx_mmio_watchdog_read,
		.write = csx_mmio_watchdog_write
	},
};

int csx_mmio_watchdog_init(csx_p csx, csx_mmio_p mmio, csx_mmio_watchdog_h h2wdt)
{
	csx_mmio_watchdog_p wdt;
	
	ERR_NULL(wdt = malloc(sizeof(csx_mmio_watchdog_t)));
	if(!wdt)
		return(-1);

	wdt->csx = csx;
	wdt->mmio = mmio;
	
	*h2wdt = wdt;
	
	csx_mmio_peripheral(mmio, &watchdog_peripheral[0], wdt);
	csx_mmio_peripheral(mmio, &watchdog_peripheral[1], wdt);
	
	return(0);
}
