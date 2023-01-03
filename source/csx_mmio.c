#include "csx_mmio.h"

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

#define _CALLBACK(_x) (_MMIO_DATA_OFFSET(_x) >> 2)
#define CSX_MMIO csx->csx_mmio

#define _MMIO_DATA_OFFSET(_x) (((_x) - CSX_MMIO_BASE) & 0x3ffff)
#define _MMIO_DATA_PAGE(_x) (((_x) - CSX_MMIO_BASE) & 0x3ff00)

static void* _mmio_data_page(csx_mmio_p mmio, uint32_t mpa)
{
	return(&mmio->data[_MMIO_DATA_PAGE(mpa)]);
}

static void* _mmio_data_offset(csx_mmio_p mmio, uint32_t mpa)
{
	return(&mmio->data[_MMIO_DATA_OFFSET(mpa)]);
}

/* **** */

void* csx_mmio_data_offset(csx_p csx, uint32_t mpa)
{
	return(_mmio_data_offset(CSX_MMIO, mpa));
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

	if(cb->rfn) {
		void* src = _mmio_data_page(mmio, mpa);
		return(cb->rfn(cb->param, src, mpa, size));
	}

	void* src = _mmio_data_offset(mmio, mpa);
	return(csx_data_read(src, size));
}

void csx_register_callback_read(csx_p csx, csx_mmio_read_fn fn, uint32_t mpa, void* param)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];

	cb->param = param;
	cb->rfn = fn;
}

void csx_register_callback_write(csx_p csx, csx_mmio_write_fn fn, uint32_t mpa, void* param)
{
	csx_mmio_p mmio = CSX_MMIO;

	csx_mmio_callback_p cb = &mmio->write[_CALLBACK(mpa)];

	cb->param = param;
	cb->wfn = fn;
}
