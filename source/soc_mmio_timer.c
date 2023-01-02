#include "soc_mmio_timer.h"

#include "csx_data.h"
#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define _TIMER(_t, _x)		(CSX_MMIO_TIMER(_t) | (_x))

#define MPU_CNTL_TIMER(_t)	_TIMER((_t), 0x00)
#define MPU_LOAD_TIMER(_t)	_TIMER((_t), 0x04)
#define MPU_READ_TIMER(_t)	_TIMER((_t), 0x08)

#define MMIO_LIST_1 \
	MMIO_TRACE_LIST_HEAD(1) \
	MMIO(0xfffe, 0xc500, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_1) \
	MMIO(0xfffe, 0xc504, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_1) \
	MMIO(0xfffe, 0xc508, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_1) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST_2 \
	MMIO_TRACE_LIST_HEAD(2) \
	MMIO(0xfffe, 0xc600, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_2) \
	MMIO(0xfffe, 0xc604, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_2) \
	MMIO(0xfffe, 0xc608, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_2) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST_3 \
	MMIO_TRACE_LIST_HEAD(3) \
	MMIO(0xfffe, 0xc700, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_3) \
	MMIO(0xfffe, 0xc704, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_3) \
	MMIO(0xfffe, 0xc708, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_3) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST \
	MMIO_LIST_1 \
	MMIO_LIST_2 \
	MMIO_LIST_3

#include "soc_mmio_trace.h"

#include "soc_mmio_ea_trace_enum.h"
MMIO_ENUM_LIST

#include "soc_mmio_ea_trace_list.h"
MMIO_TRACE_LIST

static uint32_t soc_mmio_timer_read(void* param, void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_timer_p t = param;
	const csx_p csx = t->csx;

	uint32_t value = 0;

	const ea_trace_p eat = soc_mmio_trace(csx->mmio, 0, addr);
	if(eat)
	{
		const uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;

		switch(addr)
		{
			case MPU_READ_TIMER(0):
			case MPU_READ_TIMER(1):
			case MPU_READ_TIMER(2):
				value = csx_data_read(data + (addr & 0xff), size);
				value -= (csx->cycle - t->base[timer]);
				break;
			default:
				value = csx_data_read(data + (addr & 0xff), size);
				break;
		}
	} else {
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
	}

	return(value);
}

static void soc_mmio_timer_write(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_timer_p t = param;
	const csx_p csx = t->csx;

	const ea_trace_p eat = soc_mmio_trace(csx->mmio, 0, addr);
	if(eat)
	{
		const uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;

		switch(addr)
		{
			case MPU_LOAD_TIMER(0):
			case MPU_LOAD_TIMER(1):
			case MPU_LOAD_TIMER(2):
				t->base[timer] = csx->cycle;
				break;
		}

		csx_data_write(data + (addr & 0xff), value, size);
	} else {
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

static void soc_mmio_timer_reset(void* param,
	void* data,
	soc_mmio_peripheral_p mp)
{
	const soc_mmio_timer_p t = param;

	const uint16_t module = ((mp->base - CSX_MMIO_BASE) >> 8) & 0x3ff;
	const uint8_t timer = ((mp->base - CSX_MMIO_TIMER_BASE) >> 8) & 3;

	if(0) LOG("param = 0x%08x, data = 0x%08x, module = %08x, timer = 0x%08x",
		(uint)param, (uint)data, module, timer + 1);

//	soc_mmio_trace_reset(t->mmio, mp->trace_list, module);

	t->base[timer] = 0;

	UNUSED(data, mp);
}

static soc_mmio_peripheral_t timer_peripheral[3] = {
	{
		.base = CSX_MMIO_TIMER(0),
		.trace_list = trace_list_1,

		.reset = soc_mmio_timer_reset,

		.read = soc_mmio_timer_read,
		.write = soc_mmio_timer_write
	}, {
		.base = CSX_MMIO_TIMER(1),
		.trace_list = trace_list_2,

		.reset = 0,

		.read = soc_mmio_timer_read,
		.write = soc_mmio_timer_write
	}, {
		.base = CSX_MMIO_TIMER(2),
		.trace_list = trace_list_3,

		.reset = 0,

		.read = soc_mmio_timer_read,
		.write = soc_mmio_timer_write
	},
};

int soc_mmio_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_timer_h h2t)
{
	soc_mmio_timer_p t = calloc(1, sizeof(soc_mmio_timer_t));

	ERR_NULL(t);
	if(!t)
		return(-1);

	t->csx = csx;
	t->mmio = mmio;

	*h2t = t;

	for(int i = 0; i < 3; i++) {
		t->mp[i] = &timer_peripheral[i];
		soc_mmio_peripheral(mmio, t->mp[i], t);
	}

	return(0);
}
