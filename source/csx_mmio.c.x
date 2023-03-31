#include "omap1.h"

#include "csx_mmio.h"
#include "csx_mmio_trace.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx.h"

/* **** local includes */

#include "callback_list.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

#define _CALLBACK(_x) (_MMIO_DATA_OFFSET(_x) >> 2)
#define CSX_MMIO csx->mmio

#define _MMIO_DATA_OFFSET(_x) (((_x) - TIPB_MMIO_START) & 0x3ffff)
#define _MMIO_DATA_PAGE(_x) (_MMIO_DATA_OFFSET(_x) & 0x3ff00)

static int _csx_mmio_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	csx_mmio_h h2mmio = param;
	csx_mmio_p mmio = *h2mmio;
	
	callback_list_process(&mmio->atexit_list);
	
	handle_free(param);
	
	return(0);
}

static int _csx_mmio_reset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	csx_mmio_p mmio = param;

	callback_list_process(&mmio->atreset_list);
	
	return(0);
}

static void* _mmio_data_offset(csx_mmio_p mmio, uint32_t mpa)
{
	return(&mmio->data[_MMIO_DATA_OFFSET(mpa)]);
}

static void* _mmio_data_page(csx_mmio_p mmio, uint32_t mpa)
{
	return(&mmio->data[_MMIO_DATA_PAGE(mpa)]);
}

/* **** */

void csx_mmio_callback_atexit(csx_mmio_p mmio, callback_fn fn, void* param)
{
	callback_list_register_callback(&mmio->atexit_list, fn, param);
}

void csx_mmio_callback_atreset(csx_mmio_p mmio, callback_fn fn, void* param)
{
	callback_list_register_callback(&mmio->atreset_list, fn, param);
}

void* csx_mmio_data_offset(csx_p csx, uint32_t mpa)
{
	return(_mmio_data_offset(CSX_MMIO, mpa));
}

int csx_mmio_has_callback_read(csx_p csx, uint32_t mpa)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];

	return(cb->rfn || cb->name);
}

int csx_mmio_has_callback_write(csx_p csx, uint32_t mpa)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->write[_CALLBACK(mpa)];

	return((0 != cb->wfn) || (0 != cb->name));
}

int csx_mmio_init(csx_p csx, csx_mmio_h h2mmio, void** mmio_data)
{
	if(_trace_init) {
		LOG();
	}

	assert(0 != csx);
	assert(0 != h2mmio);
	assert(0 != mmio_data);

	int err = 0;

	csx_mmio_p mmio = HANDLE_CALLOC(h2mmio, 1, sizeof(csx_mmio_t));
	ERR_NULL(mmio);

	mmio->csx = csx;

	*mmio_data = mmio->data;

	callback_list_init(&mmio->atexit_list, 0, LIST_LIFO);
	callback_list_init(&mmio->atreset_list, 0, LIST_FIFO);

	csx_callback_atexit(csx, _csx_mmio_atexit, h2mmio);
	csx_callback_atreset(csx, _csx_mmio_reset, mmio);

	return(err);
}

uint32_t csx_mmio_read(csx_p csx, uint32_t mpa, size_t size)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];

	if(cb->rfn) {
		void* src = _mmio_data_page(mmio, mpa);
		return(cb->rfn(cb->param, src, mpa, size));
	}

	void* src = _mmio_data_offset(mmio, mpa);
	uint32_t data = csx_data_read(src, size);

	if(cb->name) {
		LOG("cycle = 0x%016" PRIx64 ", %02zu:[0x%08x] >> 0x%08x: %s",
			csx->cycle, size, mpa, data, cb->name);
	} else {
		LOG("cycle = 0x%016" PRIx64 ", %02zu:[0x%08x] >> 0x%08x",
			csx->cycle, size, mpa, data);
	}

	return(data);
}

int csx_mmio_register_read(csx_p csx, csx_mmio_read_fn fn, uint32_t mpa, void* param)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];

	if(cb->param || cb->rfn)
		return(-1);

	cb->param = param;
	cb->rfn = fn;

	return(0);
}

int csx_mmio_register_trace_list(csx_p csx, csx_mmio_trace_p tl)
{
	csx_mmio_p mmio = CSX_MMIO;
	
	for(int i = 0; tl[i].mpa; i++) {
		csx_mmio_trace_p tle = &tl[i];
		
		if(0) {
			LOG("tle = 0x%08" PRIxPTR ", mpa = 0x%08x, name = %s",
				(uintptr_t)tle, tle->mpa, tle->name);
		}
		
		if(_Rw & tle->access) {
			csx_mmio_callback_p cb = &mmio->read[_CALLBACK(tle->mpa)];
			
			LOG("cb = 0x%08" PRIxPTR, (uintptr_t)cb);

			cb->name = tle->name;
			cb->size = tle->size;
		}

		if(_rW & tle->access) {
			csx_mmio_callback_p cb = &mmio->write[_CALLBACK(tle->mpa)];
			
			LOG("cb = 0x%08" PRIxPTR, (uintptr_t)cb);
			
			cb->name = tle->name;
			cb->size = tle->size;
		}
		
		mmio->reset_value[_CALLBACK(tle->mpa)] = tle->reset_value;
	}
	
	return(0);
}

int csx_mmio_register_write(csx_p csx, csx_mmio_write_fn fn, uint32_t mpa, void* param)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->write[_CALLBACK(mpa)];

	if(cb->param || cb->wfn)
		return(-1);

	cb->param = param;
	cb->wfn = fn;

	return(0);
}

void csx_mmio_write(csx_p csx, uint32_t mpa, size_t size, uint32_t data)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->write[_CALLBACK(mpa)];

	if(cb->wfn) {
		void* dst = _mmio_data_page(mmio, mpa);
		return(cb->wfn(cb->param, dst, mpa, size, data));
	}

	if(cb->name) {
		LOG("cycle = 0x%016" PRIx64 ", %02zu:[0x%08x] << 0x%08x: %s",
			csx->cycle, size, mpa, data, cb->name);
	} else {
		LOG("cycle = 0x%016" PRIx64 ", %02zu:[0x%08x] << 0x%08x",
			csx->cycle, size, mpa, data);
	}

	void* dst = _mmio_data_offset(mmio, mpa);
	return(csx_data_write(dst, size, data));
}
