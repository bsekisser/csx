#include "csx_soc_brom.h"

/* **** */

#include "csx_soc.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"
#include "libbse/include/err_test.h"
#include "libbse/include/log.h"

/* **** */

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

/* **** */

static const int prot_w = 0 ? PROT_WRITE : 0;

static
int csx_soc_brom_action_alloc_init(int err, void *const param, action_ref)
{
	ACTION_LOG(alloc);
	ERR_NULL(param);

	csx_soc_ref soc = param;

	/* **** */

	const int fd = open("boot/rom.bin", O_RDONLY);

	const int flags = MAP_PRIVATE | ((fd < 0) ? MAP_ANONYMOUS : 0);
	const int prot = PROT_READ | prot_w;

	soc->brom = mmap(0, SOC_BROM_ALLOC, prot, flags, fd, 0);
	ERR_NULL(soc->brom);

	if(MAP_FAILED == soc->brom) {
		perror("mmap");
		exit(-1);
	}

	close(fd);

	/* **** */

	return(err);
}

static
int csx_soc_brom_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);
	ERR_NULL(param);

	csx_soc_ref soc = param;

	/* **** */

	munmap(soc->brom, SOC_BROM_ALLOC);

	/* **** */

	return(err);
}

int csx_soc_brom_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	csx_soc_ref soc = param;

	csx_ref csx = soc->csx;
	ERR_NULL(csx);

	/* **** */

	armvm_mem_mmap_ro(pARMVM_MEM, SOC_BROM_START, SOC_BROM_END, soc->brom);

	/* **** */

	return(err);
}

ACTION_LIST(csx_soc_brom_action_list,
	.list = {
		[_ACTION_ALLOC_INIT] = {{ csx_soc_brom_action_alloc_init }, { 0 }, 0 },
		[_ACTION_EXIT] = {{ csx_soc_brom_action_exit }, { 0 }, 0 },
		[_ACTION_INIT] = {{ csx_soc_brom_action_init }, { 0 }, 0 },
	}
);
