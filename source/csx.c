#include "csx.h"

/* **** soc_includes */

#include "soc.h"
#include "soc_core_arm.h"

/* **** csx includes */

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

static uint32_t _csx_sdram_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write) {
	if(write)
		csx_data_offset_write(param, ppa, size, *write);
	else
		return(csx_data_offset_read(param, ppa, size));
	
	return(0);
}

static uint32_t _csx_sdram_mem_access_counted(void* param, uint32_t ppa, size_t size, uint32_t* write) {
	if(write)
		CSX_COUNTER_INC(csx_mem_access.sdram.write);
	else
		CSX_COUNTER_INC(csx_mem_access.sdram.read);
	
	return(_csx_sdram_mem_access(param, ppa, size, write));
}

static uint32_t _csx_sdram_mem_access_profiled(void* param, uint32_t ppa, size_t size, uint32_t* write) {
	volatile const uint64_t dtime = get_dtime();
	volatile const uint32_t data = _csx_sdram_mem_access(param, ppa, size, write);
	CSX_PROFILE_STAT_COUNT(csx_mem_access.sdram, dtime);
	return(data);
	UNUSED(dtime);
}

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

	void* mmio_data = 0;

	ERR(err = csx_statistics_init(csx));

	/* **** csx_mem module needs to be initialized first as others depend */

	ERR(err = csx_mem_init(csx, &csx->mem));

	csx_mem_fn fn = 0;

	if(_use_csx_sdram_mem_access) {
		fn = _csx_sdram_mem_access;

		if(_profile_csx_mem_access)
			fn = _csx_sdram_mem_access_profiled;
		else if(_csx_counter_sdram)
			fn = _csx_sdram_mem_access_counted;
	}

	csx_mem_mmap(csx, CSX_SDRAM_BASE, CSX_SDRAM_STOP, fn, csx->sdram);

	/* **** */
	ERR(err = csx_mmio_init(csx, &csx->csx_mmio, &mmio_data));
	ERR(err = csx_soc_init(csx, &csx->csx_soc));

	ERR(err = soc_mmio_init(csx, &csx->mmio, mmio_data));
	ERR(err = soc_nnd_flash_init(csx, &csx->nnd));

	return(csx);
}

void csx_reset(csx_p csx)
{
	if(_trace_atreset) {
		LOG();
	}

	callback_list_process(&csx->atreset_list);
}
