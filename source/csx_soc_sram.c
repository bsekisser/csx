#include "csx_soc_sram.h"

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
int csx_soc_sram_action_alloc_init(int err, void *const param, action_ref)
{
	ACTION_LOG(alloc);
	ERR_NULL(param);

	csx_soc_ref soc = param;

	/* **** */

	const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	const int prot = (PROT_READ | PROT_WRITE);

	soc->sram = mmap(0, SOC_SRAM_ALLOC, prot, flags, -1, 0);
	ERR_NULL(soc->sram);

	if(MAP_FAILED == soc->sram) {
		perror("mmap");
		exit(-1);
	}

	/* **** */

	return(err);
}

static
int csx_soc_sram_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);
	ERR_NULL(param);

	csx_soc_ref soc = param;

	/* **** */

	munmap(soc->sram, SOC_SRAM_ALLOC);

	/* **** */

	return(err);
}

static
int csx_soc_sram_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init, "err: 0x%08x, param: 0x%016" PRIxPTR, err, (uintptr_t)param);
	ERR_NULL(param);

	csx_soc_ref soc = param;

	csx_ref csx = soc->csx;
	ERR_NULL(csx);

	/* **** */

	armvm_mem_mmap_rw(pARMVM_MEM, SOC_SRAM_START, SOC_SRAM_END, soc->sram);

	/* **** */

	return(err);
}

ACTION_LIST(csx_soc_sram_action_list,
	.list = {
		[_ACTION_ALLOC_INIT] = {{ csx_soc_sram_action_alloc_init }, { 0 } , 0 },
		[_ACTION_EXIT] = {{ csx_soc_sram_action_exit }, { 0 } , 0 },
		[_ACTION_INIT] = {{ csx_soc_sram_action_init }, { 0 } , 0 },
	}
);

void csx_soc_sram_save(csx_soc_ref soc)
{
	FILE* fp = fopen("sram", "w");
	if(fp) {
		fwrite(soc->sram, 1, sizeof(*soc->sram), fp);
		fclose(fp);
	}
}
