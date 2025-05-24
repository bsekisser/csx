#include "soc_omap_mpu_mmc.h"

/* **** */

#include "csx_data.h"
#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"
#include "libbse/include/bitfield.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_mmc_tag {
	uint8_t data[0x100];
//
	csx_ptr csx;
	csx_mmio_ptr mmio;
}soc_omap_mpu_mmc_t;

/* **** */

static uint32_t _soc_omap_mpu_mmc_mem_access(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	soc_omap_mpu_mmc_ref mmc = param;
	csx_ref csx = mmc->csx;

	uint32_t data = csx_data_offset_mem_access(mmc->data, ppa, size, write);

	CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static csx_mmio_access_list_t __soc_omap_mpu_mmc_acl[] = {
	MMIO_TRACE_FN(0xfffb, 0x7800, 0x0000, 0x0000, MPU_MMC_CMD, _soc_omap_mpu_mmc_mem_access)
	MMIO_TRACE_FN(0xfffb, 0x7804, 0x0000, 0x0000, MPU_MMC_ARGL, _soc_omap_mpu_mmc_mem_access)
	MMIO_TRACE_FN(0xfffb, 0x7808, 0x0000, 0x0000, MPU_MMC_ARGH, _soc_omap_mpu_mmc_mem_access)
	MMIO_TRACE_FN(0xfffb, 0x7810, 0x0000, 0x0000, MPU_MMC_STAT, _soc_omap_mpu_mmc_mem_access)
	{ .ppa = ~0U, },
};

/* **** */

static
int soc_omap_mpu_mmc_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int soc_omap_mpu_mmc_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	soc_omap_mpu_mmc_ref mmc = param;

	/* **** */

	ERR_NULL(mmc->mmio);
	csx_mmio_register_access_list(mmc->mmio, 0, __soc_omap_mpu_mmc_acl, mmc);

	/* **** */

	return(err);
}

action_list_t soc_omap_mpu_mmc_action_list = {
	.list = {
		[_ACTION_EXIT] = {{ soc_omap_mpu_mmc_action_exit }, { 0 }, 0 },
		[_ACTION_INIT] = {{ soc_omap_mpu_mmc_action_init }, { 0 }, 0 },
	}
};

/* **** */

soc_omap_mpu_mmc_ptr soc_omap_mpu_mmc_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_mmc_href h2mmc)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2mmc);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_mpu_mmc_ref mmc = handle_calloc(h2mmc, 1, sizeof(soc_omap_mpu_mmc_t));
	ERR_NULL(mmc);

	mmc->csx = csx;
	mmc->mmio = mmio;

	/* **** */

	return(mmc);
}
