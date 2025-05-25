#include "csx.h"

/* **** csx includes */

#include "csx_cache.h"
#include "csx_mmio.h"
#include "csx_sdram.h"
#include "csx_soc.h"
#include "csx_statistics.h"

/* **** local includes */

#include "libarmvm/include/armvm.h"

#include "libbse/include/action.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** system includes */
/* **** */

static
int csx_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit, "err: 0x%08x, param: 0x%016" PRIxPTR, err, (uintptr_t)param);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static action_handler_t csx_action_sublist[] = {
	{{ .list = &armvm_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_t, armvm) },
	{{ .list = &csx_cache_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_t, cache) },
	{{ .list = &csx_mmio_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_t, mmio) },
	{{ .list = &csx_nnd_flash_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_t, nnd) },
	{{ .list = &csx_sdram_action_list }, { .is_list = 1 }, 0 },
	{{ .list = &csx_soc_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_t, soc) },
	{{ .list = &csx_statistics_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_t, statistics) },
	{{0}, { 0} , 0 }
};

action_list_t csx_action_list = {
	.list = {
		[_ACTION_EXIT] = {{ csx_action_exit }, { 0 }, 0 },
	},

	.sublist = csx_action_sublist,
};

int csx_action(int err, csx_ref csx, action_ref action)
{ return(action_handler(err, csx, action, &csx_action_list)); }

csx_ptr csx_alloc(csx_href h2csx)
{
	ACTION_LOG(alloc, "err: 0x%08x, param: 0x%016" PRIxPTR, 0, (uintptr_t)h2csx);

	csx_ref csx = handle_calloc(h2csx, 1, sizeof(csx_t));
	ERR_NULL(csx);

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
