#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_os_timer.h"

#define MMIO_LIST \
	MMIO(0xfffe, 0x9000, 0x00ff, 0xffff, 32, MEM_RW, OS_TIMER_TICK_VAL) \

#include "csx_mmio_trace.h"

static uint32_t csx_mmio_os_timer_read(void* data, uint32_t addr, uint8_t size)
{
	const csx_mmio_os_timer_p ost = data;
	const csx_p csx = ost->csx;
	
	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value = 0;
	
	switch(addr)
	{
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
	return(value);
}

static void csx_mmio_os_timer_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const csx_mmio_os_timer_p ost = data;
	const csx_p csx = ost->csx;
	
	csx_mmio_trace(csx->mmio, trace_list, addr);

	switch(addr)
	{
		case	OS_TIMER_TICK_VAL:
			ost->tick_val = value;
			ost->base = csx->cycle;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

static void csx_mmio_os_timer_reset(void* data)
{
	const csx_mmio_os_timer_p ost = data;
	
	ost->base = 0;
	ost->tick_val = 0;
	ost->ctrl = 0;
}

static csx_mmio_peripheral_t os_timer_peripheral = {
	.base = CSX_MMIO_OS_TIMER_BASE,

	.reset = csx_mmio_os_timer_reset,

	.read = csx_mmio_os_timer_read,
	.write = csx_mmio_os_timer_write
};

int csx_mmio_os_timer_init(csx_p csx, csx_mmio_p mmio, csx_mmio_os_timer_h h2ost)
{
	csx_mmio_os_timer_p ost;
	
	ERR_NULL(ost = malloc(sizeof(csx_mmio_os_timer_t)));
	if(!ost)
		return(-1);

	ost->csx = csx;
	ost->mmio = mmio;

	*h2ost = ost;
	
	csx_mmio_peripheral(mmio, &os_timer_peripheral, ost);

	return(0);
}
