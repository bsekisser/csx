#include "csx.h"

/* **** csx includes */

#include "csx_cache.h"
#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx_soc.h"
#include "csx_statistics.h"

/* **** */

#include "libarmvm/include/armvm.h"

/* **** local includes */

#include "libbse/include/callback_qlist.h"
#include "libbse/include/dtime.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** system includes */

#include <errno.h>
#include <libgen.h>
#include <string.h>

/* **** */

csx_p csx_alloc(void) {
	if(_trace_alloc) {
		LOG();
	}

	csx_p csx = calloc(1, sizeof(csx_t));
	ERR_NULL(csx);

	/* **** */

	callback_qlist_init(&csx->atexit_list, LIST_LIFO);
	callback_qlist_init(&csx->atreset_list, LIST_FIFO);

	/* **** */

	ERR_NULL(armvm_alloc(&csx->armvm));
	ERR_NULL(csx_cache_alloc(csx, &csx->cache));
	ERR_NULL(csx_mmio_alloc(csx, &csx->mmio));
	ERR_NULL(csx_nnd_flash_alloc(csx, &csx->nnd));
	ERR_NULL(csx_soc_alloc(csx, &csx->soc));
	ERR_NULL(csx_statistics_alloc(csx, &csx->statistics));

	/* **** */

	return(csx);
}

void csx_atexit(csx_h h2csx)
{
	if(_trace_atexit) {
		LOG(">>");
	}

	csx_p csx = *h2csx;

	callback_qlist_process(&csx->atexit_list);

	if(_trace_atexit_pedantic) {
		LOG("--");
	}

	armvm_exit(csx->armvm);

	handle_free((void**)h2csx);

	if(_trace_atexit_pedantic) {
		LOG("<<");
	}
}

void csx_callback_atexit(csx_p csx,
	callback_qlist_elem_p cble, callback_fn fn, void* param)
{
	callback_qlist_setup_and_register_callback(&csx->atexit_list, cble, fn, param);
}

void csx_callback_atreset(csx_p csx,
	callback_qlist_elem_p cble, callback_fn fn, void* param)
{
	callback_qlist_setup_and_register_callback(&csx->atreset_list, cble, fn, param);
}

csx_p csx_init(csx_p csx)
{
	ERR_NULL(csx);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	armvm_alloc_init(csx->armvm);
	csx_cache_init(csx->cache);
	csx_mmio_init(csx->mmio);
	csx_nnd_flash_init(csx->nnd);
	csx_soc_init(csx->soc);
	csx_statistics_init(csx->statistics);

	/* **** */

	armvm_mem_mmap(pARMVM_MEM, CSX_SDRAM_START, CSX_SDRAM_END, 0, csx->sdram);

	/* **** */

	return(csx);
}

void csx_reset(csx_p csx)
{
	if(_trace_atreset) {
		LOG();
	}

	armvm_reset(csx->armvm);
	callback_qlist_process(&csx->atreset_list);
}
