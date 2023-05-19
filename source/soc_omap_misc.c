#include "soc_omap_misc.h"

/* **** */

#include "csx_mmio.h"
#include "csx_data.h"
#include "csx.h"

/* **** */

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

/* **** */

static csx_mmio_access_list_t __soc_omap_misc_acl[] = {
	MMIO_TRACE_FN(0xfffe, 0x6010, 0x0000, 0x0000, xfffe_6010, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6014, 0x0000, 0x0000, xfffe_6014, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6018, 0x0000, 0x0000, xfffe_6018, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x601c, 0x0000, 0x0000, xfffe_601c, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6020, 0x0000, 0x0000, xfffe_6020, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6030, 0x0000, 0x0000, xfffe_6030, _soc_omap_misc_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6034, 0x0000, 0x0000, xfffe_6043, _soc_omap_misc_mem_access)
	{ .ppa = ~0U, },
};

int soc_omap_misc_init(csx_p csx, csx_mmio_p mmio, soc_omap_misc_h h2misc)
{
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2misc);
	
	if(_trace_init)
		LOG();
	
	soc_omap_misc_p misc = handle_calloc((void**)h2misc, 1, sizeof(soc_omap_misc_t));
	ERR_NULL(misc);
	
	misc->csx = csx;
	misc->mmio = mmio;

	csx_mmio_callback_atexit(mmio, __soc_omap_misc_atexit, h2misc);

	csx_mmio_register_access_list(mmio, 0, __soc_omap_misc_acl, misc);
	
	return(0);
}
