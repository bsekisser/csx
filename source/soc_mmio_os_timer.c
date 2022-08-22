#include "soc_mmio_os_timer.h"

#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define MMIO_LIST \
	MMIO(0xfffb, 0x9000, 0x00ff, 0xffff, 32, MEM_RW, OS_TIMER_TICK_VAL) \
	MMIO(0xfffb, 0x9008, 0x0000, 0x0008, 32, MEM_RW, OS_TIMER_CTRL)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

static uint32_t soc_mmio_os_timer_read(void* param, void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_os_timer_p ost = param;
	const csx_p csx = ost->csx;
	
	uint32_t value = soc_data_read(data + (addr & 0xff), size);;

	const ea_trace_p eat = soc_mmio_trace(csx->mmio, trace_list, addr);
	if(eat)
	{
		switch(addr)
		{
			case	OS_TIMER_CTRL:
				BCLR(value, 1);
				break;
		}
	} else {
		LOG("addr = 0x%08x, size = 0x%02x", addr, size);
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
	}

	return(value);
}

static void soc_mmio_os_timer_write(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_os_timer_p ost = param;
	const csx_p csx = ost->csx;
	
	const ea_trace_p eat = soc_mmio_trace(csx->mmio, trace_list, addr);
	if(eat)
	{
		switch(addr)
		{
			case	OS_TIMER_TICK_VAL:
				ost->base = csx->cycle;
				break;
		}
		
		soc_data_write(data + (addr & 0xff), value, size);
	} else {
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

static void soc_mmio_os_timer_reset(void* param, void* data)
{
	const soc_mmio_os_timer_p ost = param;
	
	ost->base = 0;
}

static soc_mmio_peripheral_t os_timer_peripheral = {
	.base = CSX_MMIO_OS_TIMER_BASE,

	.reset = soc_mmio_os_timer_reset,

	.read = soc_mmio_os_timer_read,
	.write = soc_mmio_os_timer_write
};

int soc_mmio_os_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_os_timer_h h2ost)
{
	soc_mmio_os_timer_p ost = calloc(1, sizeof(soc_mmio_os_timer_t));
	
	ERR_NULL(ost);
	if(!ost)
		return(-1);

	ost->csx = csx;
	ost->mmio = mmio;

	*h2ost = ost;
	
	soc_mmio_peripheral(mmio, &os_timer_peripheral, ost);

	return(0);
}
