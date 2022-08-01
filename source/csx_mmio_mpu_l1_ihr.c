#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_mpu_l1_ihr.h"

#define MMIO_LIST \
	MMIO(0xfffe, 0xcb04, 0xffff, 0xffff, 32, MEM_RW, MPU_L1_MIR)

#include "csx_mmio_trace.h"

static uint32_t csx_mmio_mpu_l1_ihr_read(void* data, uint32_t addr, uint8_t size)
{
	const csx_mmio_mpu_l1_ihr_p l1ih = data;
	const csx_p csx = l1ih->csx;
	
	if(!csx_mmio_trace(csx->mmio, trace_list, addr))
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

static void csx_mmio_mpu_l1_ihr_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const csx_mmio_mpu_l1_ihr_p l1ihr = data;
	const csx_p csx = l1ihr->csx;
	
	if(0)
		csx_mmio_peripheral_write(addr, value, l1ihr->data, trace_list);
	else
	{
		ea_trace_p eat = csx_mmio_trace(csx->mmio, trace_list, addr);

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

static void csx_mmio_mpu_l1_ihr_reset(void* data)
{
	const csx_mmio_mpu_l1_ihr_p l1ihr = data;

	csx_mmio_peripheral_reset(data, trace_list);
}

static csx_mmio_peripheral_t l1_ihr_peripheral = {
	.base = CSX_MMIO_MPU_L1_IHR_BASE,

	.reset = csx_mmio_mpu_l1_ihr_reset,

	.read = csx_mmio_mpu_l1_ihr_read,
	.write = csx_mmio_mpu_l1_ihr_write
};

int csx_mmio_mpu_l1_ihr_init(csx_p csx, csx_mmio_p mmio, csx_mmio_mpu_l1_ihr_h h2l1ihr)
{
	csx_mmio_mpu_l1_ihr_p l1ihr;
	
	ERR_NULL(l1ihr = malloc(sizeof(csx_mmio_mpu_l1_ihr_t)));
	if(!l1ihr)
		return(-1);

	l1ihr->csx = csx;
	l1ihr->mmio = mmio;

	*h2l1ihr = l1ihr;
	
	csx_mmio_peripheral(mmio, &l1_ihr_peripheral, &l1ihr->data);

	return(0);
}
