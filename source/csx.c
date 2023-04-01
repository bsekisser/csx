#include "csx.h"

/* **** soc_includes */

#include "soc.h"
#include "soc_core_arm.h"

/* **** csx includes */

#include "csx_mem.h"
#include "csx_mmio.h"
#include "csx_statistics.h"
//#include "csx_test.h"

/* **** local includes */

#include "dtime.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <libgen.h>
#include <string.h>

/* **** */

void csx_atexit(csx_h h2csx)
{
	if(_trace_atexit) {
		LOG();
	}

	csx_p csx = *h2csx;
	
	callback_list_process(&csx->atexit_list);

	handle_free((void**)h2csx);
}

void csx_callback_atexit(csx_p csx, callback_fn fn, void* param)
{
	callback_list_register_callback(&csx->atexit_list, fn, param);
}

void csx_callback_atreset(csx_p csx, callback_fn fn, void* param)
{
	callback_list_register_callback(&csx->atreset_list, fn, param);
}

csx_p csx_init(void)
{
	if(_trace_init) {
		LOG();
	}

	int err = 0;

	csx_p csx = calloc(1, sizeof(csx_t));
	ERR_NULL(csx);

	callback_list_init(&csx->atexit_list, 0, LIST_LIFO);
	callback_list_init(&csx->atreset_list, 0, LIST_FIFO);

	ERR(err = csx_statistics_init(csx));

	/* **** csx_mem module needs to be initialized first as others depend */

	ERR(err = csx_mem_init(csx, &csx->mem));

	csx_mem_mmap(csx, CSX_SDRAM_BASE, CSX_SDRAM_STOP, 0, csx->sdram);

	/* **** */

	ERR(err = csx_mmio_init(csx, &csx->mmio));
	ERR(err = csx_soc_init(csx, &csx->soc));

	// TODO: soc_nnd to csx_nnd
	ERR(err = soc_nnd_flash_init(csx, &csx->nnd));

	return(csx);
}

uint32_t csx_read(csx_p csx, uint32_t ppa, size_t size)
{
	return(csx_mem_access_read(csx, ppa, size, 0));
}

void csx_reset(csx_p csx)
{
	if(_trace_atreset) {
		LOG();
	}

	callback_list_process(&csx->atreset_list);
}

void csx_write(csx_p csx, uint32_t ppa, size_t size, uint32_t write)
{
	(void)csx_mem_access_write(csx, ppa, size, &write);
}
