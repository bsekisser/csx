#include "soc_omap_mpu_mmc.h"

/* **** */

#include "csx_data.h"
#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_mmc_t {
	csx_p csx;
	csx_mmio_p mmio;
	
	uint8_t data[0x100];
}soc_omap_mpu_mmc_t;

/* **** */

static int __soc_omap_mpu_mmc_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_omap_mpu_mmc_h h2mmc = param;
//	soc_omap_mpu_mmc_p mmc = *h2mmc;

	handle_free(param);

	return(0);
}

/* **** */

static uint32_t _soc_omap_mpu_mmc_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_mpu_mmc_p mmc = param;
	const csx_p csx = mmc->csx;

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
};

/* **** */

int soc_omap_mpu_mmc_init(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_mmc_h h2mmc)
{
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2mmc);
	
	if(_trace_init) {
		LOG();
	}

	soc_omap_mpu_mmc_p mmc = handle_calloc((void**)h2mmc, 1, sizeof(soc_omap_mpu_mmc_t));
	ERR_NULL(mmc);

	mmc->csx = csx;
	mmc->mmio = mmio;

	csx_mmio_callback_atexit(mmio, __soc_omap_mpu_mmc_atexit, h2mmc);

	/* **** */

	csx_mmio_register_access_list(mmio, 0, __soc_omap_mpu_mmc_acl, mmc);

	/* **** */

	return(0);
}
