#include "csx_mmio.h"
#include "csx_mmio_trace.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx.h"

/* **** local includes */

#include "err_test.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

#define _CALLBACK(_x) ((((_x) - CSX_MMIO_BASE) >> 8) & 0x3ff)
#define CSX_MMIO csx->csx_mmio

/* **** */

csx_callback_read_fn csx_mmio_has_callback_read(csx_p csx, uint32_t mpa)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];

	return(cb->rfn);
}

csx_callback_write_fn csx_mmio_has_callback_write(csx_p csx, uint32_t mpa)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->write[_CALLBACK(mpa)];

	return(cb->wfn);
}

int csx_mmio_init(csx_p csx, csx_mmio_h p2mmio, void** mmio_data)
{
	int err = 0;

	ERR_NULL(p2mmio);

	csx_mmio_p mmio = calloc(1, sizeof(csx_mmio_t));

	ERR_NULL(mmio);

	mmio->csx = csx;

	*p2mmio = mmio;

	*mmio_data = mmio->data;

	return(err);
}

uint32_t csx_mmio_read(csx_p csx, uint32_t mpa, uint8_t size)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];

	uint32_t data = 0;

	if(cb->rfn) {
		data = cb->rfn(cb->param, mpa, size);
	}

	CSX_MMIO_TRACE_READ(csx, mpa, size, data);

	return(data);
}

int csx_mmio_register_module_read(csx_p csx, csx_callback_read_fn fn, uint32_t mpa, void* param)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];

	if(cb->param || cb->rfn)
		return(-1);

	LOG("cb = %p, mpa >> 0x%08x", cb, mpa);

	cb->param = param;
	cb->rfn = fn;

	return(0);
}

int csx_mmio_register_write(csx_p csx, csx_callback_write_fn fn, uint32_t mpa, void* param)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->write[_CALLBACK(mpa)];

	if(cb->param || cb->wfn)
		return(-1);

	LOG("cb = %p, mpa << 0x%08x", cb, mpa);

	cb->param = param;
	cb->wfn = fn;

	return(0);
}

void csx_mmio_write(csx_p csx, uint32_t mpa, uint32_t data, uint8_t size)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->write[_CALLBACK(mpa)];

	CSX_MMIO_TRACE_WRITE(csx, mpa, size, data);

	if(cb->wfn) {
		return(cb->wfn(cb->param, mpa, size, data));
	}
}
