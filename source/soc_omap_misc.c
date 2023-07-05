#include "soc_omap_misc.h"

/* **** */

#include "csx_mmio.h"
#include "csx_data.h"
#include "csx.h"

/* **** */

#include "callback_qlist.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

typedef struct soc_omap_misc_t {
	csx_p csx;
	csx_mmio_p mmio;
	
	uint8_t data[0x100];
	uint8_t sossi[0x100];

	callback_qlist_elem_t atexit;
}soc_omap_misc_t;

/* **** */

int __soc_omap_misc_atexit(void* param)
{
	if(_trace_atexit)
		LOG();
	
	handle_free(param);
	return(0);
}

/* **** */

static uint32_t _soc_omap_misc_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;
	
	csx_data_target_t target = {
		.base = misc->data,
		.offset = ppa & 0xff,
		.size = sizeof(uint32_t),
	};
	
	uint32_t data = csx_data_target_mem_access(&target, size, write);

	switch(ppa) {
		case 0xfffe6014:
		case 0xfffe6018:
			data |= 1;
	}

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

static uint32_t _soc_omap_misc_sossi_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;
	
	csx_data_target_t target = {
		.base = misc->sossi,
		.offset = ppa & 0xff,
		.size = sizeof(uint32_t),
	};
	
	uint32_t data = csx_data_target_mem_access(&target, size, write);

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static csx_mmio_access_list_t __soc_omap_misc_acl[] = {
	MMIO_TRACE_FN(0xfffb, 0xac00, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac04, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac08, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac0c, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac10, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac14, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac18, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac1c, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac20, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
//
	MMIO_TRACE_FN(0xfffe, 0x6010, 0x0000, 0x0000, xfffe_6010, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6014, 0x0000, 0x0000, xfffe_6014, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6018, 0x0000, 0x0000, xfffe_6018, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x601c, 0x0000, 0x0000, xfffe_601c, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6020, 0x0000, 0x0000, xfffe_6020, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6030, 0x0000, 0x0000, xfffe_6030, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6034, 0x0000, 0x0000, xfffe_6043, _soc_omap_misc_mem_access)
	{ .ppa = ~0U, },
};

soc_omap_misc_p soc_omap_misc_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_misc_h h2misc)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2misc);
	
	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_omap_misc_p misc = handle_calloc((void**)h2misc, 1, sizeof(soc_omap_misc_t));
	ERR_NULL(misc);
	
	misc->csx = csx;
	misc->mmio = mmio;

	/* **** */

	csx_mmio_callback_atexit(mmio, &misc->atexit, __soc_omap_misc_atexit, h2misc);

	/* **** */
	
	return(misc);
}

void soc_omap_misc_init(soc_omap_misc_p misc)
{
	ERR_NULL(misc);
	
	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_mmio_register_access_list(misc->mmio, 0, __soc_omap_misc_acl, misc);
}
