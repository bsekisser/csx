#include "csx_sdram.h"

/* **** */

#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "libarmvm/include/armvm.h"

#include "libbse/include/action.h"
#include "libbse/include/err_test.h"

/* **** */

#include <inttypes.h>
#include <stdint.h>
#include <sys/mman.h>

/* **** */

static
int csx_sdram_action_alloc_init(int err, void *const param, action_ref)
{
	ACTION_LOG(alloc);
	ERR_NULL(param);

	csx_ref csx = param;

	/* **** */

	const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	const int prot = (PROT_READ | PROT_WRITE);

	csx->sdram = mmap(0, CSX_SDRAM_ALLOC, prot, flags, -1, 0);
	ERR_NULL(csx->sdram);

	if(MAP_FAILED == csx->sdram) {
		perror("mmap");
		exit(-1);
	}

	/* **** */

	return(err);
}

static
int csx_sdram_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);
	ERR_NULL(param);

	csx_ref csx = param;

	/* **** */

	munmap(csx->sdram, CSX_SDRAM_ALLOC);

	/* **** */

	return(err);
}

static
int csx_sdram_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init, "err: 0x%08x, param: 0x%016" PRIxPTR, err, (uintptr_t)param);
	ERR_NULL(param);

	csx_ref csx = param;

	/* **** */

	armvm_mem_mmap_rw(pARMVM_MEM, CSX_SDRAM_START, CSX_SDRAM_END, csx->sdram);

	/* **** */

	return(err);
}

ACTION_LIST(csx_sdram_action_list,
	.list = {
		[_ACTION_ALLOC_INIT] = {{ csx_sdram_action_alloc_init }, { 0 } , 0 },
		[_ACTION_EXIT] = {{ csx_sdram_action_exit }, { 0 } , 0 },
		[_ACTION_INIT] = {{ csx_sdram_action_init }, { 0 } , 0 },
	}
);

void csx_sdram_save(csx_ref csx)
{
	FILE* fp = fopen("sdram", "w");
	if(fp) {
		fwrite(csx->sdram, 1, sizeof(*csx->sdram), fp);
		fclose(fp);
	}
}
