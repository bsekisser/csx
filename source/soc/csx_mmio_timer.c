#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_timer.h"

#define _TIMER(_t, _x)		(CSX_MMIO_TIMER(_t) | (_x))

#define MPU_CNTL_TIMER(_t)	_TIMER((_t), 0x00)
#define MPU_LOAD_TIMER(_t)	_TIMER((_t), 0x04)
#define MPU_READ_TIMER(_t)	_TIMER((_t), 0x08)

#define MMIO_LIST \
	MMIO(0xfffe, 0xc700, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_3) \
	MMIO(0xfffe, 0xc704, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_3) \
	MMIO(0xfffe, 0xc708, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_3)

#include "csx_mmio_trace.h"

uint32_t csx_mmio_timer_read(csx_mmio_timer_p t, uint32_t addr, uint8_t size)
{
	csx_p csx = t->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value;
	
	switch(addr)
	{
		case MPU_READ_TIMER(0):
		case MPU_READ_TIMER(1):
		case MPU_READ_TIMER(2):
			value = csx->cycle - t->base;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
//	return(csx_data_read((uint8_t*)&value, size));
	return(value);
}

void csx_mmio_timer_write(csx_mmio_timer_p t, uint32_t addr, uint32_t value, uint8_t size)
{
	csx_p csx = t->csx;
	
	csx_mmio_trace(csx->mmio, trace_list, addr);

	
	switch(addr)
	{
		case MPU_CNTL_TIMER(0):
		case MPU_CNTL_TIMER(1):
		case MPU_CNTL_TIMER(2):
			t->cntl = value;
			break;
		case MPU_LOAD_TIMER(0):
		case MPU_LOAD_TIMER(1):
		case MPU_LOAD_TIMER(2):
			t->base = csx->cycle;
			t->value = value;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

void csx_mmio_timer_reset(csx_mmio_timer_p t)
{
	t->base = 0;
	t->value = 0;
}

int csx_mmio_timer_init(csx_p csx, csx_mmio_p mmio, csx_mmio_timer_h h2t)
{
	csx_mmio_timer_p t;
	
	ERR_NULL(t = malloc(sizeof(csx_mmio_timer_t)));
	if(!t)
		return(-1);

	t->csx = csx;
	t->mmio = mmio;
	
	*h2t = t;
	
	return(0);
}
