#include "soc_mmio_mpu_gpio.h"

#include "soc_data.h"
#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define MMIO_GPIO1_LIST \
	MMIO_TRACE_LIST_HEAD(1) \
	MMIO(0xfffb, 0xe430, 0x0000, 0x0000, 32, MEM_RW, GPIO1_DATAOUT) \
	MMIO(0xfffb, 0xe434, 0x0000, 0xffff, 32, MEM_RW, GPIO1_DIRECTION) \
	MMIO(0xfffb, 0xe4b0, 0x0000, 0x0000, 32, MEM_RW, GPIO1_CLEAR_DATAOUT) \
	MMIO(0xfffb, 0xe4f0, 0x0000, 0x0000, 32, MEM_RW, GPIO1_SET_DATAOUT) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_GPIO2_LIST \
	MMIO_TRACE_LIST_HEAD(2) \
	MMIO(0xfffb, 0xec1c, 0x0000, 0x0000, 32, MEM_RW, GPIO2_IRQENABLE2) \
	MMIO(0xfffb, 0xec30, 0x0000, 0x0000, 32, MEM_RW, GPIO2_DATAOUT) \
	MMIO(0xfffb, 0xec34, 0x0000, 0xffff, 32, MEM_RW, GPIO2_DIRECTION) \
	MMIO(0xfffb, 0xec3c, 0x0000, 0x0000, 32, MEM_RW, GPIO2_EDGE_CTRL2) \
	MMIO(0xfffb, 0xecf0, 0x0000, 0x0000, 32, MEM_RW, GPIO2_SET_DATAOUT) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_GPIO3_LIST \
	MMIO_TRACE_LIST_HEAD(3) \
	MMIO(0xfffb, 0xb430, 0x0000, 0x0000, 32, MEM_RW, GPIO3_DATAOUT) \
	MMIO(0xfffb, 0xb434, 0x0000, 0xffff, 32, MEM_RW, GPIO3_DIRECTION) \
	MMIO(0xfffb, 0xb4b0, 0x0000, 0x0000, 32, MEM_RW, GPIO3_CLEAR_DATAOUT) \
	MMIO(0xfffb, 0xb4f0, 0x0000, 0x0000, 32, MEM_RW, GPIO3_SET_DATAOUT) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_GPIO4_LIST \
	MMIO_TRACE_LIST_HEAD(4) \
	MMIO(0xfffb, 0xbc30, 0x0000, 0x0000, 32, MEM_RW, GPIO4_DATAOUT) \
	MMIO(0xfffb, 0xbc34, 0x0000, 0xffff, 32, MEM_RW, GPIO4_DIRECTION) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST \
	MMIO_GPIO1_LIST \
	MMIO_GPIO2_LIST \
	MMIO_GPIO3_LIST \
	MMIO_GPIO4_LIST

#include "soc_mmio_trace.h"

#include "soc_mmio_ea_trace_enum.h"
MMIO_ENUM_LIST

#include "soc_mmio_ea_trace_list.h"
MMIO_TRACE_LIST

static uint soc_mmio_mpu_gpio_unit(uint32_t addr)
{
	const uint32_t unit = (((addr >> 13) & 2) | ((addr >> 11) & 1)) ^ 3;

	return(unit);
}

static soc_mmio_peripheral_t mpu_gpio_peripheral[] = {
	{
		.base = CSX_MMIO_MPU_GPIO1_BASE,
		.trace_list = trace_list_1,

		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_MPU_GPIO2_BASE,
		.trace_list = trace_list_2,

		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_MPU_GPIO3_BASE,
		.trace_list = trace_list_3,

		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_MPU_GPIO4_BASE,
		.trace_list = trace_list_4,

		.reset = 0,

		.read = 0,
		.write = 0,
	},
};


int soc_mmio_mpu_gpio_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_gpio_h h2gpio)
{
	soc_mmio_mpu_gpio_p gpio = calloc(1, sizeof(soc_mmio_mpu_gpio_t));

	ERR_NULL(gpio);
	if(!gpio)
		return(-1);

	gpio->csx = csx;
	gpio->mmio = mmio;

	*h2gpio = gpio;

	for(int i = 0; i < 4; i++)
		soc_mmio_peripheral(mmio, &mpu_gpio_peripheral[i], gpio);

	return(0);
}
