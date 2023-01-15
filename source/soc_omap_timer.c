/* **** module includes */

#include "soc_omap_timer.h"

/* **** project includes */

#include "soc_omap_5912.h"

#include "csx.h"

/* **** local includes */

#include "err_test.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

enum {
	_MPU_CNTL_TIMER,
	_MPU_LOAD_TIMER = 4,
	_MPU_READ_TIMER = 8,
};

enum {
	_MPU_CNTL_TIMER_ST = 0,
	_MPU_CNTL_TIMER_AR = 1,
	_MPU_CNTL_TIMER_CLOCK_ENABLE = 5,
	_MPU_CNTL_TIMER_FREE = 6,
//
	_MPU_CNTL_TIMER_CE_ST = _MPU_CNTL_TIMER_CLOCK_ENABLE | _MPU_CNTL_TIMER_ST,
	_MPU_CNTL_TIMER_AR_CE_ST = _MPU_CNTL_TIMER_AR | _MPU_CNTL_TIMER_CE_ST,
};

CSX_MMIO_DATAREG_GET(MPU_CNTL_TIMER, uint32_t);
CSX_MMIO_DATAREG_RMW(MPU_CNTL_TIMER, uint32_t);
CSX_MMIO_DATAREG_SET(MPU_CNTL_TIMER, uint32_t);
CSX_MMIO_DATAREG_GET(MPU_LOAD_TIMER, uint32_t);
CSX_MMIO_DATAREG_SET(MPU_LOAD_TIMER, uint32_t);
CSX_MMIO_DATAREG_GET(MPU_READ_TIMER, uint32_t);

CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, AR);
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, CLOCK_ENABLE);
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, FREE);
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, ST);

/* **** */

static uint32_t __timer_update_count(soc_omap_timer_p sot, void* data)
{
	csx_p csx = sot->csx;

	if(!BEXT(sot->cntl, _MPU_CNTL_TIMER_ST))
		return(0);

	if(!BEXT(sot->cntl, _MPU_CNTL_TIMER_CLOCK_ENABLE))
		return(0);

	uint64_t elapsed_cycles = csx->cycle - sot->cycle;
	sot->cycle = csx->cycle;

/*
 * NOTE: produces wrong expected value.
 *		compiler error? typesize promotion fault?
 * 
 *		gcc version 10.2.1 20210110 (Raspbian 10.2.1-6+rpi1)
 *
 * int64_t delta64_count = sot->count - elapsed_cycles;
 */

	int32_t delta_count = sot->count - elapsed_cycles;

//	LOG("elapsed_cycles = 0x%016" PRIx64 ", delta_count = 0x%08x, count = 0x%08x",
//		elapsed_cycles, delta_count, sot->count);

	if(0 >= delta_count) {
		if(MPU_CNTL_TIMER_AR(data)) {
			sot->count = delta_count + MPU_LOAD_TIMER(data, 0);
		} else {
			MPU_CNTL_TIMER_RMW(data, _MPU_CNTL_TIMER_ST, _MMIO_BIC);
			sot->count = 0;
		}
	} else
		sot->count -= delta_count;

	return(sot->count);
}

/* **** */

static void _mpu_cntl_timer_r(void* param, uint32_t mpa, uint8_t size)
{
	const soc_omap_timer_p sot = param;
//	const csx_p csx = sot->csx;

	return(sot->cntl);
}

static void _mpu_cntl_timer_w(void* param, void* data, uint32_t mpa, uint32_t value, uint8_t size)
{
	const soc_omap_timer_p sot = param;
	const csx_p csx = sot->csx;

	if(!MPU_CNTL_TIMER_RMW(data, value, _MMIO_TEQ))
		return;

	CSX_MMIO_TRACE_WRITE(csx, mpa, size, data);

	LOG_START("\n\tRESERVED[31:7] = 0x%08x", mlBFEXT(value, 31, 7));
		_LOG_(", FREE[6] = %01u", BEXT(value, 6));
		_LOG_(", CLOCK_ENABLE[5] = %01u", BEXT(value, 5));
		uint8_t ptv = mlBFEXT(value, 4, 2);
		_LOG_(", PTV[4:2] = %01u(%03u)", ptv, 2 << ptv);
		_LOG_(", AR[1] = %01u", BEXT(value, 1));
		_LOG_(", ST[0] = %01u", BEXT(value, 0));
	LOG_END();

	int cntl_st = MPU_CNTL_TIMER_ST(data);
	int new_cntl_st = BEXT(value, _MPU_CNTL_TIMER_ST);
	int start = new_cntl_st && (cntl_st ^ new_cntl_st);

	MPU_CNTL_TIMER_SET(data, value, size);

	if(start) {
		sot->cycle = csx->cycle;
		sot->count = sot->load;
	} else
		__timer_update_count(sot, data);
}

static void _mpu_load_timer_w(void* param, void* data, uint32_t mpa, uint32_t value, uint8_t size)
{
	const soc_omap_timer_p sot = param;
	const csx_p csx = sot->csx;

	CSX_MMIO_TRACE_WRITE(csx, mpa, size, value);
	LOG("count = 0x%08x", sot->count);

	__timer_update_count(sot, data);

	MPU_LOAD_TIMER_SET(data, value, size);
}

static uint32_t _mpu_read_timer_r(void* param, uint32_t mpa, uint8_t size)
{
	const soc_omap_timer_p sot = param;
	const csx_p csx = sot->csx;
	void* data = sot->data;

	uint32_t count = __timer_update_count(sot, data);

	CSX_MMIO_TRACE_READ(csx, mpa, size, data);

	return(count);
}

/* **** */

static uint32_t soc_omap_timer_read(void* param, uint32_t mpa, uint8_t size)
{
//	const soc_omap_timer_p sot = param;
//	const csx_p csx = sot->csx;

	switch(mpa & 0xff) {
		case	_MPU_READ_TIMER:
			return(_mpu_read_timer_r(param, mpa, size));
//
		case	_MPU_CNTL_TIMER:
			return(_mpu_cntl_timer_r(param, mpa, size));
	}
	
	CSX_MMIO_INVALID_READ(csx);

	return(0);
}

uint32_t soc_omap_timer_list[3] = {
	SOC_MPU_TIMER1_BASE, SOC_MPU_TIMER2_BASE, SOC_MPU_TIMER3_BASE
};

int soc_omap_timer_init(csx_p csx, soc_omap_timer_h h2t, int i)
{
	int err = 0;

	soc_omap_timer_p t = calloc(1, sizeof(soc_omap_timer_t));
	ERR_NULL(t);

	*h2t = t;
	t->csx = csx;

	/* **** */

	ERR(err = csx_mmio_register_module_read(csx,
		soc_omap_timer_read, soc_omap_timer_list[i], t);
		
	ERR(err = csx_mmio_register_module_write(csx,
		soc_omap_timer_write, soc_omap_timer_list[i], t);

	/* **** */

	return(err);
}
