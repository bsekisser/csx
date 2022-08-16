#include "soc_mmio_mpu_ihr.h"

#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define MMIO_LIST \
	MMIO(0xfffe, 0x0000, 0x0000, 0x0000, 32, MEM_RW, MPU_L2_ITR) \
	MMIO(0xfffe, 0x0004, 0xffff, 0xffff, 32, MEM_RW, MPU_L2_MIR) \
	MMIO(0xfffe, 0xcb04, 0xffff, 0xffff, 32, MEM_RW, MPU_L1_MIR)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

static soc_mmio_peripheral_t ihr_peripheral[] = {
	{
		.base = CSX_MMIO_MPU_L1_IHR_BASE,
		.trace_list = trace_list,

	//	.reset = soc_mmio_mpu_ihr_reset,

	//	.read = soc_mmio_mpu_ihr_read,
	//	.write = soc_mmio_mpu_ihr_write
	}, {
		.base = CSX_MMIO_MPU_L2_IHR_BASE,
		.trace_list = trace_list,
	},
};

int soc_mmio_mpu_ihr_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_ihr_h h2ihr)
{
	soc_mmio_mpu_ihr_p ihr;
	
	ERR_NULL(ihr = malloc(sizeof(soc_mmio_mpu_ihr_t)));
	if(!ihr)
		return(-1);

	ihr->csx = csx;
	ihr->mmio = mmio;

	*h2ihr = ihr;
	
	soc_mmio_peripheral(mmio, &ihr_peripheral[0], ihr);
	soc_mmio_peripheral(mmio, &ihr_peripheral[1], ihr);

	return(0);
}
