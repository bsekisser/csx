#include "soc_mmio_mpu_mmc.h"

#include "csx_data.h"
#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define MMIO_LIST_0 \
	MMIO_TRACE_LIST_HEAD(mmc1) \
	MMIO(0xfffb, 0x7800, 0x0000, 0x0000, 16, MEM_RW, MPU_MMC_CMD) \
	MMIO(0xfffb, 0x7804, 0x0000, 0x0000, 16, MEM_RW, MPU_MMC_ARGL) \
	MMIO(0xfffb, 0x7808, 0x0000, 0x0000, 16, MEM_RW, MPU_MMC_ARGH) \
	MMIO(0xfffb, 0x7810, 0x0000, 0x0000, 16, MEM_RW, MPU_MMC_STAT) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST \
	MMIO_LIST_0 \

#include "soc_mmio_trace.h"

#include "soc_mmio_ea_trace_enum.h"
MMIO_ENUM_LIST

#include "soc_mmio_ea_trace_list.h"
MMIO_TRACE_LIST

/* **** */

UNUSED_FN static uint32_t soc_mmio_mpu_mmc_read(void* param, void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_mpu_mmc_p mmc = param;
	const csx_p csx = mmc->csx;

	uint32_t value = csx_data_read(data + (addr & 0xff), size);;

	const ea_trace_p eat = soc_mmio_trace(csx->mmio, 0, addr);
	if(eat)
	{
		switch(addr)
		{
		}
	} else {
		LOG("addr = 0x%08x, size = 0x%02x", addr, size);
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
	}

	return(value);
}

UNUSED_FN static void soc_mmio_mpu_mmc_write(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_mpu_mmc_p mmc = param;
	const csx_p csx = mmc->csx;

	const ea_trace_p eat = soc_mmio_trace(csx->mmio, 0, addr);
	if(eat)
	{
		switch(addr)
		{
			case	MPU_MMC_CMD:
				break;
		}

		csx_data_write(data + (addr & 0xff), value, size);
	} else {
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

static soc_mmio_peripheral_t mpu_mmc_peripheral[2] = {
	{
		.base = CSX_MMIO_MPU_MMC1_BASE,
		.trace_list = trace_list_mmc1,

		.reset = 0,

		.read = 0,
		.write = 0,

	},
};

/* **** */

int soc_mmio_mpu_mmc_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_mmc_h h2mmc)
{
	soc_mmio_mpu_mmc_p mmc = calloc(1, sizeof(soc_mmio_mpu_mmc_t));

	ERR_NULL(mmc);
	if(!mmc)
		return(-1);

	mmc->csx = csx;
	mmc->mmio = mmio;

	*h2mmc = mmc;

	soc_mmio_peripheral(mmio, &mpu_mmc_peripheral[0], mmc);
	soc_mmio_peripheral(mmio, &mpu_mmc_peripheral[1], mmc);

	return(0);
}
