#include "csx.h"
#include "soc_mmio.h"

#include "soc_mmio_omap.h"

#include "soc_mmio_os_timer.h"

#define MMIO_LIST \
	MMIO(0xfffb, 0x9000, 0x00ff, 0xffff, 32, MEM_RW, OS_TIMER_TICK_VAL) \
	MMIO(0xfffb, 0x9008, 0x0000, 0x0008, 32, MEM_RW, OS_TIMER_CTRL)

#include "soc_mmio_trace.h"

static uint32_t soc_mmio_os_timer_read(void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_os_timer_p ost = data;
	const csx_p csx = ost->csx;
	
	soc_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value = 0;
	
	switch(addr)
	{
		case	OS_TIMER_CTRL:
			value = BCLR(ost->ctrl, 1);
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
	return(value);
}

static void soc_mmio_os_timer_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_os_timer_p ost = data;
	const csx_p csx = ost->csx;
	
	soc_mmio_trace(csx->mmio, trace_list, addr);

	switch(addr)
	{
		case	OS_TIMER_CTRL:
			ost->ctrl = value;
			break;
		case	OS_TIMER_TICK_VAL:
			ost->tick_val = value;
			ost->base = csx->cycle;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

static void soc_mmio_os_timer_reset(void* data)
{
	const soc_mmio_os_timer_p ost = data;
	
	ost->base = 0;
	ost->tick_val = 0;
	ost->ctrl = 0;
}

static soc_mmio_peripheral_t os_timer_peripheral = {
	.base = CSX_MMIO_OS_TIMER_BASE,

	.reset = soc_mmio_os_timer_reset,

	.read = soc_mmio_os_timer_read,
	.write = soc_mmio_os_timer_write
};

int soc_mmio_os_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_os_timer_h h2ost)
{
	soc_mmio_os_timer_p ost;
	
	ERR_NULL(ost = malloc(sizeof(soc_mmio_os_timer_t)));
	if(!ost)
		return(-1);

	ost->csx = csx;
	ost->mmio = mmio;

	*h2ost = ost;
	
	soc_mmio_peripheral(mmio, &os_timer_peripheral, ost);

	return(0);
}
