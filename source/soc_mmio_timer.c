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

enum {
	_MPU_CNTL_TIMER,
	_MPU_LOAD_TIMER = 4,
	_MPU_READ_TIMER = 8,
};

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

/* **** */

SOC_DATA_BIT_DECL(_MPU_CNTL_TIMER, _AR, 1, sizeof(uint32_t));
SOC_DATA_BIT_DECL(_MPU_CNTL_TIMER, _CLOCK_ENABLE, 5, sizeof(uint32_t));
SOC_DATA_BIT_DECL(_MPU_CNTL_TIMER, _FREE, 6, sizeof(uint32_t));
SOC_DATA_BIT_DECL(_MPU_CNTL_TIMER, _ST, 0, sizeof(uint32_t));

static void _mpu_cntl_timer_w(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_timer_unit_p smtu = param;
	const soc_mmio_timer_p timer = smtu->timer;
	const csx_p csx = timer->csx;

//	const uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;

	csx_data_write(data + _MPU_CNTL_TIMER, value, size);

	if(csx_data_bit_read(data, &_MPU_CNTL_TIMER_ST)) {
		smtu->base = csx->cycle;
		if(!smtu->count)
			smtu->count = csx_data_read(data + _MPU_LOAD_TIMER, sizeof(uint32_t));
	}

	LOG("base = 0x%016"PRIx64", count = 0x%08x, value = 0x%08x",
		smtu->base, smtu->count, value);

	UNUSED(addr);
}

static void _mpu_load_timer_w(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
//	const soc_mmio_timer_unit_p smtu = param;
//	const soc_mmio_timer_p timer = smtu->timer;
//	const csx_p csx = timer->csx;

//	const uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;
	
	LOG("value = 0x%08x", value);
	
	csx_data_write(data + _MPU_LOAD_TIMER, value, size);

	UNUSED(addr, data, param, value, size);
}

static uint32_t _mpu_read_timer_r(void* param, void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_timer_unit_p smtu = param;
	const soc_mmio_timer_p timer = smtu->timer;
	const csx_p csx = timer->csx;

//	const uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;

	uint32_t elapsed = csx->cycle - smtu->base;
	smtu->base = csx->cycle;

	if(csx_data_bit_read(data, &_MPU_CNTL_TIMER_ST)) {
		int32_t delta_count = smtu->count - elapsed;

		uint reload = elapsed > smtu->count;

		smtu->count -= elapsed;

		uint ar = reload ? csx_data_bit_read(data, &_MPU_CNTL_TIMER_AR) : 0;

		if(ar) {
			smtu->count = 0;

			uint32_t load = csx_data_read(data + _MPU_LOAD_TIMER, size);

			smtu->count = load + delta_count;

			LOG(":AR: base = 0x%016"PRIx64", count = 0x%08x, elapsed = 0x%08x, load = 0x%08x, delta = 0x%08x",
				smtu->base, smtu->count, elapsed, load, delta_count);
		} else {
			LOG(" base = 0x%016"PRIx64", count = 0x%08x, elapsed = 0x%08x, delta = 0x%08x",
				smtu->base, smtu->count, elapsed, delta_count);
		}
	}
	
	return(smtu->count);

	UNUSED(addr);
}

/* **** */

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

	t->unit[timer].base = 0;

	UNUSED(data, mp);
}

static soc_mmio_peripheral_t timer_peripheral[3] = {
	{
		.base = CSX_MMIO_TIMER(0),
		.trace_list = trace_list_1,

		.reset = soc_mmio_timer_reset,
	}, {
		.base = CSX_MMIO_TIMER(1),
		.trace_list = trace_list_2,
	}, {
		.base = CSX_MMIO_TIMER(2),
		.trace_list = trace_list_3,
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
		
		soc_mmio_timer_unit_p smtu = &t->unit[i];
		
		smtu->timer = t;
		
		soc_mmio_register_read(csx, MPU_READ_TIMER(i), _mpu_read_timer_r, smtu);
		soc_mmio_register_write(csx, MPU_CNTL_TIMER(i), _mpu_cntl_timer_w, smtu);
		soc_mmio_register_write(csx, MPU_LOAD_TIMER(i), _mpu_load_timer_w, smtu);
	}

	return(0);
}
