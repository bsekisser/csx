#include "soc_omap_usb.h"

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx_data.h"
#include "csx.h"

/* **** local library level includes */

#include "libbse/include/callback_qlist.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/mem_access.h"
#include "libbse/include/unused.h"

/* **** */

#include "errno.h"
#include "string.h"

/* **** */

typedef struct soc_omap_usb_tag {
	csx_ptr csx;
	csx_mmio_ptr mmio;

	struct {
		uint32_t syscon1;
	}otg;

	uint8_t data[0x100];

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}soc_omap_usb_t;

/* **** */

//static void ___set_reset_done(soc_omap_usb_ref usb, const int set)
//{ BMAS(usb>syscon_1, 2, set); }

/* **** */

static int __soc_omap_usb_atexit(void *const param)
{
	ACTION_LOG(exit);

	handle_free(param);
	return(0);
}

static int __soc_omap_usb_atreset(void *const param)
{
	ACTION_LOG(reset);

//	soc_omap_usb_ref usb = param;
//	___set_reset_done(param, 1);

	return(0);
	UNUSED(param);
}

/* **** */

static uint32_t _soc_omap_usb_client_mem_access(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	soc_omap_usb_ref usb = param;
	csx_ref csx = usb->csx;

	const uint8_t offset = ppa & 0xff;

	const uint32_t data = csx_data_offset_mem_access(usb->data, offset, size, write);

	if(_trace_mmio_usb_client)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

static uint32_t _soc_omap_usb_otg_mem_access(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_usb_ref usb = param;
	csx_ref csx = usb->csx;

	uint32_t data = 0xdeadbeef;
	const uint8_t offset = ppa & 0xff;

	switch(offset) {
		case 4: // usb_otg_syscon1
			data = mem_32_access(&usb->otg.syscon1, write) | _BV(2);
			break;
	}

	if(_trace_mmio_usb_client)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}


/* **** */

static csx_mmio_access_list_t _soc_omap_usb_client_acl[] = {
	MMIO_TRACE_FN(0xfffb, 0x0404, 0x0000, 0x0000, USB_OTG_SYSCON1, _soc_omap_usb_otg_mem_access)
	MMIO_TRACE_FN(0xfffb, 0x4018, 0x0000, 0x0000, USB_CLNT_SYSCON1, _soc_omap_usb_client_mem_access)
	{ .ppa = ~0U, },
};

soc_omap_usb_ptr soc_omap_usb_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_usb_href h2usb)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2usb);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_usb_ref usb = handle_calloc((void**)h2usb, 1, sizeof(soc_omap_usb_t));
	ERR_NULL(usb);

	usb->csx = csx;
	usb->mmio = mmio;

	csx_mmio_callback_atexit(mmio, &usb->atexit, __soc_omap_usb_atexit, h2usb);
	csx_mmio_callback_atreset(mmio, &usb->atreset, __soc_omap_usb_atreset, usb);

	/* **** */

	return(usb);
}


void soc_omap_usb_init(soc_omap_usb_ref usb)
{
	ACTION_LOG(init);
	ERR_NULL(usb);

	/* **** */

	csx_mmio_register_access_list(usb->mmio, 0, _soc_omap_usb_client_acl, usb);
}
