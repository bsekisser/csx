#include "soc_mmio_mpu_gpio.h"

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
	MMIO_GPIO1_LIST \
	MMIO_GPIO2_LIST \
	MMIO_GPIO3_LIST \
	MMIO_GPIO4_LIST

#define MMIO_GPIO1_LIST \
	MMIO(0xfffb, 0xe430, 0x0000, 0x0000, 32, MEM_RW, GPIO1_DATAOUT) \
	MMIO(0xfffb, 0xe434, 0x0000, 0xffff, 32, MEM_RW, GPIO1_DIRECTION)

#define MMIO_GPIO2_LIST \
	MMIO(0xfffb, 0xec30, 0x0000, 0x0000, 32, MEM_RW, GPIO2_DATAOUT) \
	MMIO(0xfffb, 0xec34, 0x0000, 0xffff, 32, MEM_RW, GPIO2_DIRECTION)

#define MMIO_GPIO3_LIST \
	MMIO(0xfffb, 0xb430, 0x0000, 0x0000, 32, MEM_RW, GPIO3_DATAOUT) \
	MMIO(0xfffb, 0xb434, 0x0000, 0xffff, 32, MEM_RW, GPIO3_DIRECTION)

#define MMIO_GPIO4_LIST \
	MMIO(0xfffb, 0xbc30, 0x0000, 0x0000, 32, MEM_RW, GPIO4_DATAOUT) \
	MMIO(0xfffb, 0xbc34, 0x0000, 0xffff, 32, MEM_RW, GPIO4_DIRECTION)
	
#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST


static uint soc_mmio_mpu_gpio_unit(uint32_t addr)
{
	uint32_t unit = (((addr >> 13) & 2) | ((addr >> 11) & 1)) ^ 3;

	return(unit);
}

static soc_mmio_peripheral_t mpu_gpio_peripheral[] = {
	[0] = {
		.base = CSX_MMIO_MPU_GPIO1_BASE,
		.trace_list = trace_list,

//		.reset = soc_mmio_mpu_gpio_reset,

//		.read = soc_mmio_mpu_gpio_read,
//		.write = soc_mmio_mpu_gpio_write,
	},
	[1] = {
		.base = CSX_MMIO_MPU_GPIO2_BASE,
		.trace_list = trace_list,

//		.reset = soc_mmio_mpu_gpio_reset,

//		.read = soc_mmio_mpu_gpio_read,
//		.write = soc_mmio_mpu_gpio_write,
	},
	[2] = {
		.base = CSX_MMIO_MPU_GPIO3_BASE,
		.trace_list = trace_list,

//		.reset = soc_mmio_mpu_gpio_reset,

//		.read = soc_mmio_mpu_gpio_read,
//		.write = soc_mmio_mpu_gpio_write,
	},
	[3] = {
		.base = CSX_MMIO_MPU_GPIO4_BASE,
		.trace_list = trace_list,

//		.reset = soc_mmio_mpu_gpio_reset,

//		.read = soc_mmio_mpu_gpio_read,
//		.write = soc_mmio_mpu_gpio_write,
	},
};


int soc_mmio_mpu_gpio_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_gpio_h h2gpio)
{
	soc_mmio_mpu_gpio_p gpio;
	
	ERR_NULL(gpio = malloc(sizeof(soc_mmio_mpu_gpio_t)));
	if(!gpio)
		return(-1);

	gpio->csx = csx;
	gpio->mmio = mmio;
	
	*h2gpio = gpio;
	
	for(int i = 0; i < 4; i++)
		soc_mmio_peripheral(mmio, &mpu_gpio_peripheral[i], gpio);
	
	return(0);
}
