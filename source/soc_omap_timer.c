/* **** module includes */

#include "soc_omap_timer.h"

/* **** project includes */

#include "soc_omap_5912.h"

#include "csx.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

CSX_MMIO_DATAREG_GET(MPU_CNTL_TIMER, uint32_t)
CSX_MMIO_DATAREG_GET(MPU_LOAD_TIMER, uint32_t)
CSX_MMIO_DATAREG_GET(MPU_READ_TIMER, uint32_t)

CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, AR, 1);
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, CLOCK_ENABLE, 5, sizeof(uint32_t));
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, FREE, 6, sizeof(uint32_t));
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, ST, 0, sizeof(uint32_t));

static void _mpu_cntl_timer_w(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_omap_timer_p sot = param;
	const csx_p csx = sot->csx;

	MPU_CNTL_TIMER_SET(data, value);

	if(MPU_CNTL_TIMER_ST(data)) {
		sot->base = csx->cycle;
		if(!sot->count)
			sot->count = MPU_LOAD_TIMER();
	}

	LOG("base = 0x%016"PRIx64", count = 0x%08x, value = 0x%08x",
		sot->base, sot->count, value);

	UNUSED(addr);
}

void soc_omap_timer_init(csx_p csx, soc_omap_timer_p t)
{
	csx_mmio_register_read(csx, t->r_mpu_read_timer, _mpu_read_timer_r, sot);
	csx_mmio_register_write(csx, t->r_mpu_cntl_timer, _mpu_cntl_timer_w, sot);
	csx_mmio_register_write(csx, t->r_mpu_load_timer, _mpu_load_timer_w, sot);
}
