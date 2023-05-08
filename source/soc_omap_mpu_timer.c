#include "soc_omap_mpu_timer.h"

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** local includes */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_timer_unit_t* soc_omap_mpu_timer_unit_p;
typedef struct soc_omap_mpu_timer_unit_t {
		uint64_t cycle;

		uint32_t cntl_data;
		uint32_t count;
		uint32_t load;

		struct{
			/* ---01 -- 1 */	uint32_t ar:1;
			/* ---05 -- 1 */	uint32_t clock_enable:1;
			/* ---06 -- 1 */	uint32_t free:1;
			/* 04:02 -- 3 */	uint32_t ptv:3;
			/* ---00 -- 1 */	uint32_t st:1;
		}cntl;
}soc_omap_mpu_timer_unit_t;

typedef struct soc_omap_mpu_timer_t {
	csx_p csx;
	csx_mmio_p mmio;

	soc_omap_mpu_timer_unit_t unit[3];
}soc_omap_mpu_timer_t;

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

#define MPU_TIMERt_BASE(_t) (SOC_OMAP_MPU_TIMER1 + ((_t) << 8))
#define MPU_TIMER_(_t, _x) (MPU_TIMERt_BASE(_t) + _MPU_TIMER_NAME(_x))

#define MPU_TIMER_NAME(_t, _x)  MPU_ ## _x ## _TIMER ## _t
#define _MPU_TIMER_NAME(_x)  _MPU_ ## _x ## _TIMER

/* **** */

static void __mpu_timer_cntl_write(soc_omap_mpu_timer_unit_p sotu, uint32_t data)
{
	sotu->cntl.ar = BEXT(data, _MPU_CNTL_TIMER_AR);
	sotu->cntl.clock_enable = BEXT(data, _MPU_CNTL_TIMER_CLOCK_ENABLE);
	sotu->cntl.free = BEXT(data, _MPU_CNTL_TIMER_FREE);
	sotu->cntl.ptv = mlBFEXT(data, 4, 2);
	sotu->cntl.st = BEXT(data, _MPU_CNTL_TIMER_ST);
}

static soc_omap_mpu_timer_unit_p
__mpu_timer_unit(soc_omap_mpu_timer_p sot, uint32_t ppa) {
	unsigned tu = ppa - SOC_OMAP_MPU_TIMER1;
	tu >>= 8;
	tu &= 3;
	
	return(&sot->unit[tu]);
}

static int __soc_omap_mpu_timer_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_omap_mpu_timer_h h2t = param;
//	soc_omap_mpu_timer_p t = *h2t;

	handle_free(param);

	return(0);
}

static int __soc_omap_mpu_timer_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	soc_omap_mpu_timer_p t = param;

	for(unsigned i = 0; i < 3; i++) {
		soc_omap_mpu_timer_unit_p sotu = &t->unit[i];
		
		memset(sotu, 0, sizeof(soc_omap_mpu_timer_unit_t));
//		sotu->cntl_data = 0;

	/* load undefined */
	/* read undefined */
	}

	return(0);
}

static uint32_t __timer_update_count(soc_omap_mpu_timer_p sot, soc_omap_mpu_timer_unit_p sotu)
{
	csx_p csx = sot->csx;

#if 0
	assert(0 != data);
	assert(0 != sot);

	if(0) LOG("csx = 0x%08" PRIxPTR ", data = 0x%08" PRIxPTR ", sot = 0x%08" PRIxPTR ", sot_unit = 0x%08" PRIxPTR,
		csx, data, sot, sotu);
#endif

	if(!(sotu->cntl.st || sotu->cntl.clock_enable))
		return(0);

	if(0) {
		LOG_START("csx->cycle = 0x%016" PRIx64, csx->cycle);
		_LOG_(", sot->cycle = 0x%016" PRIx64, (uint64_t)sotu->cycle);
		_LOG_(", sot->count = 0x%016" PRIx64, (uint64_t)sotu->count);
		LOG_END();
	}

	const unsigned elapsed_cycles = csx->cycle - sotu->cycle;
	sotu->cycle = csx->cycle;

/*
 * NOTE: produces wrong expected value.
 *		compiler error? typesize promotion fault?
 *
 *		gcc version 10.2.1 20210110 (Raspbian 10.2.1-6+rpi1)
 *
 * int64_t delta64_count = sot->count - elapsed_cycles;
 */

	const unsigned delta_count = sotu->count - elapsed_cycles;

	if(0) {
		LOG_START("elapsed_cycles = 0x%016" PRIx64, (uint64_t)elapsed_cycles)
		_LOG_(", delta_count = 0x%016" PRIx64, (uint64_t)delta_count);
		LOG_END();
	}

	if(elapsed_cycles >= sotu->count) {
		unsigned cycles_remain = elapsed_cycles - sotu->count;
		if(sotu->cntl.ar) {
			sotu->count = sotu->load - cycles_remain;
		} else {
			sotu->cntl.st = 0;
			sotu->count = 0;
		}
	} else
		sotu->count -= elapsed_cycles;

	return(sotu->count);
}

/* **** */

static uint32_t _soc_omap_mpu_timer_cntl(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_mpu_timer_p sot = param;
	const soc_omap_mpu_timer_unit_p sotu = __mpu_timer_unit(sot, ppa);
	
	const csx_p csx = sot->csx;

	uint32_t data = write ? *write : 0;

	if(write) {
		unsigned was_st = sotu->cntl.st;

		__mpu_timer_cntl_write(sotu, data);

		unsigned start = sotu->cntl.st && was_st ^ sotu->cntl.st;

		sotu->cntl_data = data;

		if(_trace_mmio_mpu_timer) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
			LOG_START("\n\tRESERVED[31:7] = 0x%08x", mlBFEXT(data, 31, 7));
				_LOG_(", FREE[6] = %01u", sotu->cntl.free);
				_LOG_(", CLOCK_ENABLE[5] = %01u", sotu->cntl.clock_enable);
				_LOG_(", PTV[4:2] = %01u(%03u)", sotu->cntl.ptv, 2 << sotu->cntl.ptv);
				_LOG_(", AR[1] = %01u", sotu->cntl.ar);
				_LOG_(", ST[0] = %01u", sotu->cntl.st);
			LOG_END();
		}

		if(start) {
			sotu->cycle = csx->cycle;
			sotu->count = sotu->load;
		} else
			__timer_update_count(sot, sotu);
	} else
		return(sotu->cntl_data);

	return(data);
}

static uint32_t _soc_omap_mpu_timer_load(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_mpu_timer_p sot = param;
	const soc_omap_mpu_timer_unit_p sotu = __mpu_timer_unit(sot, ppa);
	const csx_p csx = sot->csx;

	if(_trace_mmio_mpu_timer) {
		LOG_START("cycle = 0x%016" PRIx64 ", %02zu:[0x%08x] << 0x%08x",
			csx->cycle, size, ppa, *write);
		LOG_END(", count = 0x%08x", sotu->count);
	}

	__timer_update_count(sot, sotu);

	sotu->load = *write;

	return(*write);
}

static uint32_t _soc_omap_mpu_timer_read(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_mpu_timer_p sot = param;
	const soc_omap_mpu_timer_unit_p sotu = __mpu_timer_unit(sot, ppa);
	const csx_p csx = sot->csx;

	uint32_t count = __timer_update_count(sot, sotu);

	if(_trace_mmio_mpu_timer)
		CSX_MMIO_TRACE_READ(csx, ppa, size, count);

	return(count);
	
	UNUSED(write);
}

#define _MPU_TIMER_ACLE(_i, _name, _fn) \
	{ __MMIO_TRACE_FN(MPU_TIMER_(_i, _name), 0, MPU_TIMER_NAME(_i, _name), _fn) },

int soc_omap_mpu_timer_init(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_timer_h h2t)
{
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2t);

	if(_trace_init) {
		LOG();
	}

	int err = 0;

	soc_omap_mpu_timer_p t = handle_calloc((void**)h2t, 1, sizeof(soc_omap_mpu_timer_t));
	ERR_NULL(t);

	t->csx = csx;
	t->mmio = mmio;

	csx_mmio_callback_atexit(mmio, __soc_omap_mpu_timer_atexit, h2t);
	csx_mmio_callback_atreset(mmio, __soc_omap_mpu_timer_atreset, t);

	/* **** */

	for(unsigned i = 0; i < 3; i++) {
		csx_mmio_access_list_t _soc_omap_mpu_timer_acl[4] = {
			_MPU_TIMER_ACLE(i, CNTL, _soc_omap_mpu_timer_cntl)
			_MPU_TIMER_ACLE(i, LOAD, _soc_omap_mpu_timer_load)
			_MPU_TIMER_ACLE(i, READ, _soc_omap_mpu_timer_read)
			{ .ppa = ~0U, }
		};
		
		csx_mmio_register_access_list(mmio, 0, _soc_omap_mpu_timer_acl, t);
	}

	/* **** */

	return(err);
}
