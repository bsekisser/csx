#include "soc_omap_mpu_timer.h"

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** local includes */

#include "libbse/include/bitfield.h"
#include "libbse/include/callback_qlist.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/sub64.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_timer_unit_tag* soc_omap_mpu_timer_unit_ptr;
typedef soc_omap_mpu_timer_unit_ptr const soc_omap_mpu_timer_unit_ref;

typedef struct soc_omap_mpu_timer_unit_tag {
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

typedef struct soc_omap_mpu_timer_tag {
	csx_ptr csx;
	csx_mmio_ptr mmio;

	soc_omap_mpu_timer_unit_t unit[3];

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
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

static void __mpu_timer_cntl_write(soc_omap_mpu_timer_unit_ref sotu, const uint32_t data)
{
	sotu->cntl.ar = BEXT(data, _MPU_CNTL_TIMER_AR);
	sotu->cntl.clock_enable = BEXT(data, _MPU_CNTL_TIMER_CLOCK_ENABLE);
	sotu->cntl.free = BEXT(data, _MPU_CNTL_TIMER_FREE);
	sotu->cntl.ptv = mlBFEXT(data, 4, 2);
	sotu->cntl.st = BEXT(data, _MPU_CNTL_TIMER_ST);
}

static soc_omap_mpu_timer_unit_ptr
__mpu_timer_unit(soc_omap_mpu_timer_ref sot, const uint32_t ppa) {
	unsigned tu = ppa - SOC_OMAP_MPU_TIMER1;
	tu >>= 8;
	tu &= 3;

	return(&sot->unit[tu]);
}

static int __soc_omap_mpu_timer_atexit(void *const param)
{
	ACTION_LOG(exit);

//	soc_omap_mpu_timer_href h2t = param;
//	soc_omap_mpu_timer_ref t = *h2t;

	handle_ptrfree(param);

	return(0);
}

static int __soc_omap_mpu_timer_atreset(void *const param)
{
	ACTION_LOG(reset);

	soc_omap_mpu_timer_ref t = param;

	for(unsigned i = 0; i < 3; i++) {
		soc_omap_mpu_timer_unit_ref sotu = &t->unit[i];

		memset(sotu, 0, sizeof(soc_omap_mpu_timer_unit_t));
//		sotu->cntl_data = 0;

	/* load undefined */
	/* read undefined */
	}

	return(0);
}

static uint32_t __timer_update_count(soc_omap_mpu_timer_ref sot, soc_omap_mpu_timer_unit_ref sotu)
{
	csx_ref csx = sot->csx;
	const uint64_t csx_cycle = CYCLE;

#if 0
	assert(0 != data);
	assert(0 != sot);

	if(0) LOG("csx = 0x%08" PRIxPTR ", data = 0x%08" PRIxPTR ", sot = 0x%08" PRIxPTR ", sot_unit = 0x%08" PRIxPTR,
		csx, data, sot, sotu);
#endif

	if(!(sotu->cntl.st || sotu->cntl.clock_enable))
		return(0);

	if(0) {
		LOG_START("csx->cycle = 0x%016" PRIx64, csx_cycle);
		_LOG_(", sot->cycle = 0x%016" PRIx64, (uint64_t)sotu->cycle);
		_LOG_(", sot->count = 0x%016" PRIx64, (uint64_t)sotu->count);
		LOG_END();
	}

	const int64_t elapsed_cycles = sub64(csx_cycle, sotu->cycle);
	sotu->cycle = csx_cycle;

	const int64_t delta_count = sub64(sotu->count, elapsed_cycles);

	if(0) {
		LOG_START("elapsed_cycles = 0x%016" PRIx64, (uint64_t)elapsed_cycles)
		_LOG_(", delta_count = 0x%016" PRIx64, (uint64_t)delta_count);
		LOG_END();
	}

	if(delta_count < 0) {
		const unsigned cycles_remain = elapsed_cycles - sotu->count;
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

static uint32_t _soc_omap_mpu_timer_cntl(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	soc_omap_mpu_timer_ref sot = param;
	soc_omap_mpu_timer_unit_ref sotu = __mpu_timer_unit(sot, ppa);

	csx_ref csx = sot->csx;

	uint32_t data = write ? *write : 0;

	if(write) {
		const unsigned was_st = sotu->cntl.st;

		__mpu_timer_cntl_write(sotu, data);

		const unsigned start = sotu->cntl.st && was_st ^ sotu->cntl.st;

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
			sotu->cycle = CYCLE;
			sotu->count = sotu->load;
		} else
			__timer_update_count(sot, sotu);
	} else
		return(sotu->cntl_data);

	return(data);
}

static uint32_t _soc_omap_mpu_timer_load(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	soc_omap_mpu_timer_ref sot = param;
	soc_omap_mpu_timer_unit_ref sotu = __mpu_timer_unit(sot, ppa);
	csx_ref csx = sot->csx;

	if(_trace_mmio_mpu_timer) {
		LOG_START("cycle = 0x%016" PRIx64 ", %02zu:[0x%08x] << 0x%08x",
			CYCLE, size, ppa, *write);
		LOG_END(", count = 0x%08x", sotu->count);
	}

	__timer_update_count(sot, sotu);

	sotu->load = *write;

	return(*write);
}

static uint32_t _soc_omap_mpu_timer_read(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	soc_omap_mpu_timer_ref sot = param;
	soc_omap_mpu_timer_unit_ref sotu = __mpu_timer_unit(sot, ppa);
	csx_ref csx = sot->csx;

	const uint32_t count = __timer_update_count(sot, sotu);

	if(_trace_mmio_mpu_timer)
		CSX_MMIO_TRACE_READ(csx, ppa, size, count);

	return(count);

	UNUSED(write);
}

#define _MPU_TIMER_ACLE(_i, _name, _fn) \
	{ __MMIO_TRACE_FN(MPU_TIMER_(_i, _name), 0, MPU_TIMER_NAME(_i, _name), _fn) },

soc_omap_mpu_timer_ptr soc_omap_mpu_timer_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_timer_href h2t)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2t);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_mpu_timer_ref t = handle_calloc(h2t, 1, sizeof(soc_omap_mpu_timer_t));
	ERR_NULL(t);

	t->csx = csx;
	t->mmio = mmio;

	csx_mmio_callback_atexit(mmio, &t->atexit, __soc_omap_mpu_timer_atexit, h2t);
	csx_mmio_callback_atreset(mmio, &t->atreset, __soc_omap_mpu_timer_atreset, t);

	/* **** */

	return(t);
}

void soc_omap_mpu_timer_init(soc_omap_mpu_timer_ref t)
{
	ACTION_LOG(init);
	ERR_NULL(t);

	csx_mmio_ref mmio = t->mmio;

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
}
