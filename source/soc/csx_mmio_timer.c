#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_timer.h"

#define _TIMER(_t, _x)		(CSX_MMIO_TIMER(_t) | (_x))

#define MPU_CNTL_TIMER(_t)	_TIMER((_t), 0x00)
#define MPU_LOAD_TIMER(_t)	_TIMER((_t), 0x04)
#define MPU_READ_TIMER(_t)	_TIMER((_t), 0x08)

#define MMIO_LIST \
	MMIO(0xfffe, 0xc500, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_1) \
	MMIO(0xfffe, 0xc504, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_1) \
	MMIO(0xfffe, 0xc508, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_1) \
	MMIO(0xfffe, 0xc600, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_2) \
	MMIO(0xfffe, 0xc604, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_2) \
	MMIO(0xfffe, 0xc608, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_2) \
	MMIO(0xfffe, 0xc700, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_3) \
	MMIO(0xfffe, 0xc704, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_3) \
	MMIO(0xfffe, 0xc708, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_3)

#include "csx_mmio_trace.h"

static uint32_t csx_mmio_timer_read(void* data, uint32_t addr, uint8_t size)
{
	const csx_mmio_timer_p t = data;
	const csx_p csx = t->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;
	uint32_t value;
	
	switch(addr)
	{
		case MPU_READ_TIMER(0):
		case MPU_READ_TIMER(1):
		case MPU_READ_TIMER(2):
			value = csx->cycle - t->unit[timer].base;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
//	return(csx_data_read((uint8_t*)&value, size));
	return(value);
}

static void csx_mmio_timer_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const csx_mmio_timer_p t = data;
	const csx_p csx = t->csx;
	
	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;
	
	switch(addr)
	{
		case MPU_CNTL_TIMER(0):
		case MPU_CNTL_TIMER(1):
		case MPU_CNTL_TIMER(2):
			t->unit[timer].cntl = value;
			break;
		case MPU_LOAD_TIMER(0):
		case MPU_LOAD_TIMER(1):
		case MPU_LOAD_TIMER(2):
			t->unit[timer].base = csx->cycle;
			t->unit[timer].value = value;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

static void csx_mmio_timer_reset(void* data)
{
	const csx_mmio_timer_p t = data;
	
	for(int i = 0; i < 3; i++)
	{
		t->unit[i].base = 0;
		t->unit[i].value = 0;
	}
}

static csx_mmio_peripheral_t timer_peripheral[3] = {
	[0] = {
		.base = CSX_MMIO_TIMER(0),

		.reset = csx_mmio_timer_reset,

		.read = csx_mmio_timer_read,
		.write = csx_mmio_timer_write
	},
	[1] = {
		.base = CSX_MMIO_TIMER(1),

//		.reset = csx_mmio_timer_reset,

		.read = csx_mmio_timer_read,
		.write = csx_mmio_timer_write
	},
	[2] = {
		.base = CSX_MMIO_TIMER(2),

//		.reset = csx_mmio_timer_reset,

		.read = csx_mmio_timer_read,
		.write = csx_mmio_timer_write
	},
};

int csx_mmio_timer_init(csx_p csx, csx_mmio_p mmio, csx_mmio_timer_h h2t)
{
	csx_mmio_timer_p t;
	
	ERR_NULL(t = malloc(sizeof(csx_mmio_timer_t)));
	if(!t)
		return(-1);

	t->csx = csx;
	t->mmio = mmio;
	
	*h2t = t;

	for(int i = 0; i < 3; i++)
		csx_mmio_peripheral(mmio, &timer_peripheral[i], t);
	
	return(0);
}
