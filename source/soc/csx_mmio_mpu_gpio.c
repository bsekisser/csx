#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_mpu_gpio.h"

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
	
#include "csx_mmio_trace.h"

static uint32_t csx_mmio_mpu_gpio_read(void* data, uint32_t addr, uint8_t size)
{
	const csx_mmio_mpu_xgpio_p xgpio = data;
	const csx_mmio_mpu_gpio_p gpio = xgpio->gpio;
	const csx_mmio_p mmio = gpio->mmio;
	const csx_p csx = gpio->csx;

	ea_trace_p eat = csx_mmio_trace(mmio, trace_list, addr);
	if(eat)
	{
		uint32_t value = csx_data_read(&xgpio->data[addr & 0xff], size);
		
		switch(addr)
		{
		}
		
	//	return(csx_data_read((uint8_t*)&value, size));
		return(value);
	}

	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
	return(0);
}

static void csx_mmio_mpu_gpio_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const csx_mmio_mpu_xgpio_p xgpio = data;
	const csx_mmio_mpu_gpio_p gpio = xgpio->gpio;
	const csx_mmio_p mmio = gpio->mmio;
	const csx_p csx = gpio->csx;

	ea_trace_p eat = csx_mmio_trace(mmio, trace_list, addr);
	if(eat)
	{
		switch(addr)
		{
		}

		return(csx_data_write(&xgpio->data[addr & 0xff], value, size));
	}

	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
}

static void csx_mmio_mpu_gpio_reset(void* data)
{
	const csx_mmio_mpu_xgpio_p xgpio = data;
	const csx_mmio_mpu_gpio_p gpio = xgpio->gpio;
	const csx_mmio_p mmio = gpio->mmio;
//	const csx_p csx = gpio->csx;
	
	csx_mmio_trace_reset(mmio, trace_list, xgpio->data, xgpio->base);
}

static csx_mmio_peripheral_t mpu_gpio_peripheral[] = {
	[0] = {
		.base = CSX_MMIO_MPU_GPIO1_BASE,

		.reset = csx_mmio_mpu_gpio_reset,

		.read = csx_mmio_mpu_gpio_read,
		.write = csx_mmio_mpu_gpio_write,
	},
	[1] = {
		.base = CSX_MMIO_MPU_GPIO2_BASE,

		.reset = csx_mmio_mpu_gpio_reset,

		.read = csx_mmio_mpu_gpio_read,
		.write = csx_mmio_mpu_gpio_write,
	},
	[2] = {
		.base = CSX_MMIO_MPU_GPIO3_BASE,

		.reset = csx_mmio_mpu_gpio_reset,

		.read = csx_mmio_mpu_gpio_read,
		.write = csx_mmio_mpu_gpio_write,
	},
	[3] = {
		.base = CSX_MMIO_MPU_GPIO4_BASE,

		.reset = csx_mmio_mpu_gpio_reset,

		.read = csx_mmio_mpu_gpio_read,
		.write = csx_mmio_mpu_gpio_write,
	},
};


int csx_mmio_mpu_gpio_init(csx_p csx, csx_mmio_p mmio, csx_mmio_mpu_gpio_h h2gpio)
{
	csx_mmio_mpu_gpio_p gpio;
	
	ERR_NULL(gpio = malloc(sizeof(csx_mmio_mpu_gpio_t)));
	if(!gpio)
		return(-1);

	gpio->csx = csx;
	gpio->mmio = mmio;
	
	*h2gpio = gpio;
	
	for(int i = 0; i < 4; i++)
	{
		gpio->x[i].base = mpu_gpio_peripheral[i].base;
		gpio->x[i].gpio = gpio;
		csx_mmio_peripheral(mmio, &mpu_gpio_peripheral[i], &gpio->x[i]);
	}
	
	return(0);
}
