#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_mpu_gpio.h"

#define MMIO_LIST \
	MMIO(0xfffb, 0xb430, 0x0000, 0x0000, 32, MEM_RW, GPIO3_DATAOUT) \
	MMIO(0xfffb, 0xb434, 0x0000, 0xffff, 32, MEM_RW, GPIO3_DIRECTION) \
	MMIO(0xfffb, 0xbc30, 0x0000, 0x0000, 32, MEM_RW, GPIO4_DATAOUT) \
	MMIO(0xfffb, 0xbc34, 0x0000, 0xffff, 32, MEM_RW, GPIO4_DIRECTION) \
	MMIO(0xfffb, 0xe430, 0x0000, 0x0000, 32, MEM_RW, GPIO1_DATAOUT) \
	MMIO(0xfffb, 0xe434, 0x0000, 0xffff, 32, MEM_RW, GPIO1_DIRECTION) \
	MMIO(0xfffb, 0xec30, 0x0000, 0x0000, 32, MEM_RW, GPIO2_DATAOUT) \
	MMIO(0xfffb, 0xec34, 0x0000, 0xffff, 32, MEM_RW, GPIO2_DIRECTION)

#include "csx_mmio_trace.h"

uint32_t csx_mmio_mpu_gpio_read(csx_mmio_mpu_gpio_p gpio, uint32_t addr, uint8_t size)
{
	csx_p csx = gpio->csx;

	ea_trace_p eat = csx_mmio_trace(csx->mmio, trace_list, addr);
	if(eat)
	{
		uint32_t value = csx_data_read(&gpio->data[addr & 0xff], size);
		
		switch(addr)
		{
		}
		
	//	return(csx_data_read((uint8_t*)&value, size));
		return(value);
	}

	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
	return(0);
}

void csx_mmio_mpu_gpio_write(csx_mmio_mpu_gpio_p gpio, uint32_t addr, uint32_t value, uint8_t size)
{
	csx_p csx = gpio->csx;

	ea_trace_p eat = csx_mmio_trace(csx->mmio, trace_list, addr);
	if(eat)
	{
		switch(addr)
		{
		}

		return(csx_data_write(&gpio->data[addr & 0xff], value, size));
	}

	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
}

void csx_mmio_mpu_gpio_reset(csx_mmio_mpu_gpio_p gpio)
{
	csx_mmio_trace_reset(gpio->mmio, trace_list, gpio->data);
}

int csx_mmio_mpu_gpio_init(csx_p csx, csx_mmio_p mmio, csx_mmio_mpu_gpio_h h2gpio)
{
	csx_mmio_mpu_gpio_p gpio;
	
	ERR_NULL(gpio = malloc(sizeof(csx_mmio_mpu_gpio_t)));
	if(!gpio)
		return(-1);

	gpio->csx = csx;
	gpio->mmio = mmio;
	
	*h2gpio = gpio;
	
	return(0);
}
