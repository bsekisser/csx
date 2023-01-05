/* **** module includes */

#include "soc_omap_timer.h"

/* **** project includes */

#include "soc_omap_5912.h"

#include "csx.h"

/* **** local includes */

#include "err_test.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

enum {
	_MPU_CNTL_TIMER,
	_MPU_LOAD_TIMER = 4,
	_MPU_READ_TIMER = 8,
};

CSX_MMIO_DATAREG_GET(MPU_CNTL_TIMER, uint32_t)
CSX_MMIO_DATAREG_GET(MPU_LOAD_TIMER, uint32_t)
CSX_MMIO_DATAREG_GET(MPU_READ_TIMER, uint32_t)

CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, AR, 1);
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, CLOCK_ENABLE, 5);
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, FREE, 6);
CSX_MMIO_DATAREGBIT_GET(MPU_CNTL_TIMER, ST, 0);

static void _mpu_cntl_timer_w(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_omap_timer_p sot = param;
	const csx_p csx = sot->csx;

	MPU_CNTL_TIMER(data, &value, size);

	if(MPU_CNTL_TIMER_ST(data)) {
		sot->base_cycle = csx->cycle;
		if(!sot->count)
			sot->count = MPU_LOAD_TIMER(data, 0, size);
	}

	LOG("cycle = 0x%016"PRIx64", count = 0x%08x, value = 0x%08x",
		sot->base_cycle, sot->count, value);

	UNUSED(addr);
}

int soc_omap_timer_init(csx_p csx, soc_omap_timer_h h2t, int i)
{
	int err = 0;

	soc_omap_timer_p t = calloc(1, sizeof(soc_omap_timer_t));
	ERR_NULL(t);

	*h2t = t;
	t->csx = csx;

	/* **** */

//	CSX_MMIO_REG_DECL(r_mpu_cntl_timer, MPU_TIMER_(i, CNTL), uint32_t);
//	CSX_MMIO_REG_DECL(r_mpu_load_timer, MPU_TIMER_(i, LOAD), uint32_t);
//	CSX_MMIO_REG_DECL(r_mpu_read_timer, MPU_TIMER_(i, READ), uint32_t);

//	ERR(err = csx_mmio_register_read(csx,
//		r_mpu_read_timer, _mpu_read_timer_r, t));

//	ERR(err = csx_mmio_register_write(csx,
//		r_mpu_cntl_timer, _mpu_cntl_timer_w, t));

	ERR(err = csx_mmio_register_write(csx, _mpu_cntl_timer_w,
		MPU_TIMER_(i, CNTL), t));


//	ERR(err = csx_mmio_register_write(csx,
//		r_mpu_load_timer, _mpu_load_timer_w, t));

	/* **** */

	return(err);
}
