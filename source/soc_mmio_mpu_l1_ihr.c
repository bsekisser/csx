#include "soc_mmio_mpu_l1_ihr.h"

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
	MMIO(0xfffe, 0xcb04, 0xffff, 0xffff, 32, MEM_RW, MPU_L1_MIR)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

static uint32_t soc_mmio_mpu_l1_ihr_read(void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_mpu_l1_ihr_p l1ih = data;
	const csx_p csx = l1ih->csx;
	
	if(!soc_mmio_trace(csx->mmio, trace_list, addr))
	{
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
	}	

	uint32_t value = 0;
	
	switch(addr)
	{
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
	return(value);
}

static void soc_mmio_mpu_l1_ihr_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_mpu_l1_ihr_p l1ihr = data;
	const csx_p csx = l1ihr->csx;
	
	if(0)
		soc_mmio_peripheral_write(addr, value, l1ihr->data, trace_list);
	else
	{
		ea_trace_p eat = soc_mmio_trace(csx->mmio, trace_list, addr);

		switch(addr)
		{
			default:
				if(!eat)
				{
					LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
				}
				break;
		}
	}
}

static void soc_mmio_mpu_l1_ihr_reset(void* data)
{
//	const soc_mmio_mpu_l1_ihr_p l1ihr = data;

	soc_mmio_peripheral_reset(data, trace_list);
}

static soc_mmio_peripheral_t l1_ihr_peripheral = {
	.base = CSX_MMIO_MPU_L1_IHR_BASE,

	.reset = soc_mmio_mpu_l1_ihr_reset,

	.read = soc_mmio_mpu_l1_ihr_read,
	.write = soc_mmio_mpu_l1_ihr_write
};

int soc_mmio_mpu_l1_ihr_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_l1_ihr_h h2l1ihr)
{
	soc_mmio_mpu_l1_ihr_p l1ihr;
	
	ERR_NULL(l1ihr = malloc(sizeof(soc_mmio_mpu_l1_ihr_t)));
	if(!l1ihr)
		return(-1);

	l1ihr->csx = csx;
	l1ihr->mmio = mmio;

	*h2l1ihr = l1ihr;
	
	soc_mmio_peripheral(mmio, &l1_ihr_peripheral, &l1ihr->data);

	return(0);
}
