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

csx_ptr csx_alloc(void) {
	ACTION_LOG(alloc);

	csx_ref csx = calloc(1, sizeof(csx_t));
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

void csx_atexit(csx_href h2csx)
{
	ACTION_LOG(exit);

	csx_ref csx = *h2csx;

	callback_qlist_process(&csx->atexit_list);

	armvm_exit(csx->armvm);

	handle_ptrfree(h2csx);
}

void csx_callback_atexit(csx_ref csx,
	callback_qlist_elem_p const cble, callback_fn const fn, void *const param)
{
	callback_qlist_setup_and_register_callback(&csx->atexit_list, cble, fn, param);
}

void csx_callback_atreset(csx_ref csx,
	callback_qlist_elem_p const cble, callback_fn const fn, void *const param)
{
	callback_qlist_setup_and_register_callback(&csx->atreset_list, cble, fn, param);
}

csx_ptr csx_init(csx_ref csx)
{
	ACTION_LOG(init);
	ERR_NULL(csx);

	/* **** */

	armvm_alloc_init(csx->armvm);
	csx_cache_init(csx->cache);
	csx_mmio_init(csx->mmio);
	csx_nnd_flash_init(csx->nnd);
	csx_soc_init(csx->soc);
	csx_statistics_init(csx->statistics);

	/* **** */

	armvm_mem_mmap_rw(pARMVM_MEM, CSX_SDRAM_START, CSX_SDRAM_END, csx->sdram);

	/* **** */

	return(csx);
}

void csx_reset(csx_ref csx)
{
	ACTION_LOG(reset);

	armvm_reset(csx->armvm);
	callback_qlist_process(&csx->atreset_list);
}
