#include "soc_omap_usb.h"

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx_data.h"
#include "csx.h"

/* **** local library level includes */

#include "err_test.h"
#include "handle.h"
#include "log.h"
#include "unused.h"

/* **** */

#include "errno.h"
#include "string.h"

/* **** */

typedef struct soc_omap_usb_t {
		csx_p csx;
		csx_mmio_p mmio;

		uint8_t data[0x100];
}soc_omap_usb_t;

/* **** */

int __soc_omap_usb_atexit(void* param)
{
	if(_trace_atexit)
		LOG();

	handle_free(param);
	return(0);
}

UNUSED_FN int __soc_omap_usb_atreset(void* param)
{
	if(_trace_atreset)
		LOG();

//	soc_omap_usb_p usb = param;

	return(0);

	UNUSED(param);
}

/* **** */

static uint32_t _soc_omap_usb_client_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_usb_p usb = param;
	const csx_p csx = usb->csx;

	const uint8_t offset = ppa & 0xff;

	const uint32_t data = csx_data_offset_mem_access(usb->data, offset, size, write);

	if(_trace_mmio_usb_client)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static csx_mmio_access_list_t _soc_omap_usb_client_acl[] = {
	MMIO_TRACE_FN(0xfffb, 0x4018, 0x0000, 0x0000, USB_CLNT_SYSCON1, _soc_omap_usb_client_mem_access)
	{ .ppa = ~0U, },
};

int soc_omap_usb_init(csx_p csx, csx_mmio_p mmio, soc_omap_usb_h h2usb)
{
	if(_trace_init)
		LOG();

	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2usb);

	soc_omap_usb_p usb = handle_calloc((void**)h2usb, 1, sizeof(soc_omap_usb_t));
	ERR_NULL(usb);

	usb->csx = csx;
	usb->mmio = mmio;

	csx_mmio_callback_atexit(mmio, __soc_omap_usb_atexit, h2usb);
//	csx_mmio_callback_atreset(mmio, __soc_omap_usb_atreset, usb);

	csx_mmio_register_access_list(mmio, 0, _soc_omap_usb_client_acl, usb);

	return(0);
}
