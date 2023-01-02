/* **** module includes */

/* **** project includes */

#include "soc_omap_5912.h"

#include "csx_mmio.h"
#include "csx_data.h"
#include "csx.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

#define _CALLBACK(_x) (_CALLBACK_MPA(_x) >> 1)
#define _CALLBACK_MPA(_x) ((_x) - SOC_MMIO_START)

#define csx2mmio csx->csx_mmio

/* **** */

void* _mmio_data(csx_mmio_p mmio, uint32_t mpa)
{
	return(&mmio->data[_CALLBACK_MPA(mpa) & 0x3ff00]);
}

void* _mmio_data_mpa(csx_mmio_p mmio, uint32_t mpa)
{
	return(&mmio->data[_CALLBACK_MPA(mpa) & 0x3ffff]);
}

void _mmio_data_write(csx_mmio_p mmio, uint32_t mpa, uint32_t data, size_t size)
{
	void* dst = _mmio_data(mmio, mpa);

	dst += (mpa & 0x1ff);

	csx_data_write(dst, data, size);
}

/* **** */

void* csx_mmio_data(csx_p csx, uint32_t mpa)
{
	return(_mmio_data(csx2mmio, mpa));
}

void* csx_mmio_data_mpa(csx_p csx, uint32_t mpa)
{
	return(_mmio_data_mpa(csx2mmio, mpa));
}

uint32_t csx_mmio_read(csx_p csx, uint32_t mpa, size_t size)
{
	csx_mmio_p mmio = csx2mmio;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];
	void* src = _mmio_data(mmio, mpa);

	if(cb->rfn)
		return(cb->rfn(cb->param, src, mpa, size));

	return(csx_data_read(src + (mpa & 0xff), size));
}

void csx_mmio_register_read(csx_p csx, uint32_t mpa, csx_mmio_read_fn fn, void* param)
{
	csx_mmio_p mmio = csx2mmio;

	csx_mmio_callback_p cb = &mmio->read[_CALLBACK(mpa)];

	cb->rfn = fn;
	cb->param = param;
}

void csx_mmio_register_write(csx_p csx, uint32_t mpa, csx_mmio_write_fn fn, void* param)
{
	csx_mmio_p mmio = csx2mmio;

	csx_mmio_callback_p cb = &mmio->write[_CALLBACK(mpa)];

	cb->wfn = fn;
	cb->param = param;
}
