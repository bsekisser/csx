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

static uint32_t soc_mmio_mpu_gpio_read(void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_mpu_gpio_p gpio = data;
	const soc_mmio_p mmio = gpio->mmio;
	const csx_p csx = gpio->csx;

	ea_trace_p eat = soc_mmio_trace(mmio, trace_list, addr);
	if(eat)
	{
		uint32_t unit = (((addr >> 13) & 2) | ((addr >> 11) & 1)) ^ 3;
		
		uint32_t value = soc_data_read(&gpio->data[unit][addr & 0xff], size);
		
		switch(addr)
		{
		}
		
	//	return(soc_data_read((uint8_t*)&value, size));
		return(value);
	}

	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
	return(0);
}

static void soc_mmio_mpu_gpio_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_mpu_gpio_p gpio = data;
	const soc_mmio_p mmio = gpio->mmio;
	const csx_p csx = gpio->csx;

	ea_trace_p eat = soc_mmio_trace(mmio, trace_list, addr);
	if(eat)
	{
		uint32_t unit = (((addr >> 13) & 2) | ((addr >> 11) & 1)) ^ 3;

		switch(addr)
		{
		}

		return(soc_data_write(&gpio->data[unit][addr & 0xff], value, size));
	}

	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
}

static void soc_mmio_mpu_gpio_reset(void* data)
{
	const soc_mmio_mpu_gpio_p gpio = data;
//	const soc_mmio_p mmio = gpio->mmio;
//	const csx_p csx = gpio->csx;
	
	for(int unit = 0; unit < 4; unit++)
	{
		for(int i = 0; i < 256; i++)
			gpio->data[unit][i] = 0;
	}
	
	int i = 0;
	do {
		ea_trace_p tle = &trace_list[i++];

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		uint32_t value = tle->reset_value;
		if(value)
		{
			uint32_t addr = tle->address;
			uint32_t unit = (((addr >> 13) & 2) | ((addr >> 11) & 1)) ^ 3;
			soc_data_write(&gpio->data[unit][addr & 0xff], value, tle->size);
		}
	}while(trace_list[i].address);
}

static soc_mmio_peripheral_t mpu_gpio_peripheral[] = {
	[0] = {
		.base = CSX_MMIO_MPU_GPIO1_BASE,

		.reset = soc_mmio_mpu_gpio_reset,

		.read = soc_mmio_mpu_gpio_read,
		.write = soc_mmio_mpu_gpio_write,
	},
	[1] = {
		.base = CSX_MMIO_MPU_GPIO2_BASE,

//		.reset = soc_mmio_mpu_gpio_reset,

		.read = soc_mmio_mpu_gpio_read,
		.write = soc_mmio_mpu_gpio_write,
	},
	[2] = {
		.base = CSX_MMIO_MPU_GPIO3_BASE,

//		.reset = soc_mmio_mpu_gpio_reset,

		.read = soc_mmio_mpu_gpio_read,
		.write = soc_mmio_mpu_gpio_write,
	},
	[3] = {
		.base = CSX_MMIO_MPU_GPIO4_BASE,

//		.reset = soc_mmio_mpu_gpio_reset,

		.read = soc_mmio_mpu_gpio_read,
		.write = soc_mmio_mpu_gpio_write,
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
