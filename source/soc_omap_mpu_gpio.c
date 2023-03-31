#include "soc_omap_mpu_gpio.h"

#include "csx_soc_omap.h"
#include "csx_data.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_gpio_t {
	csx_p csx;
	csx_mmio_p mmio;
	uint8_t data[4][0x100];
}soc_omap_mpu_gpio_t;

/* **** */

#define SOC_OMAP_MPU_GPIO_ACLE(_ahi, _alo, _dhi, _dlo, _name) \
	MMIO_TRACE_FN(_ahi, _alo, _dhi, _dlo, _name, _soc_omap_mpu_gpio_mem_access)

#define SOC_OMAP_MPU_GPIO1_LIST(_MMIO) \
	_MMIO(0xfffb, 0xe430, 0x0000, 0x0000, GPIO1_DATAOUT) \
	_MMIO(0xfffb, 0xe434, 0x0000, 0xffff, GPIO1_DIRECTION) \
	_MMIO(0xfffb, 0xe4b0, 0x0000, 0x0000, GPIO1_CLEAR_DATAOUT) \
	_MMIO(0xfffb, 0xe4f0, 0x0000, 0x0000, GPIO1_SET_DATAOUT) \

#define SOC_OMAP_MPU_GPIO2_LIST(_MMIO) \
	_MMIO(0xfffb, 0xec1c, 0x0000, 0x0000, GPIO2_IRQENABLE2) \
	_MMIO(0xfffb, 0xec30, 0x0000, 0x0000, GPIO2_DATAOUT) \
	_MMIO(0xfffb, 0xec34, 0x0000, 0xffff, GPIO2_DIRECTION) \
	_MMIO(0xfffb, 0xec3c, 0x0000, 0x0000, GPIO2_EDGE_CTRL2) \
	_MMIO(0xfffb, 0xecf0, 0x0000, 0x0000, GPIO2_SET_DATAOUT) \

#define SOC_OMAP_MPU_GPIO3_LIST(_MMIO) \
	_MMIO(0xfffb, 0xb430, 0x0000, 0x0000, GPIO3_DATAOUT) \
	_MMIO(0xfffb, 0xb434, 0x0000, 0xffff, GPIO3_DIRECTION) \
	_MMIO(0xfffb, 0xb4b0, 0x0000, 0x0000, GPIO3_CLEAR_DATAOUT) \
	_MMIO(0xfffb, 0xb4f0, 0x0000, 0x0000, GPIO3_SET_DATAOUT) \

#define SOC_OMAP_MPU_GPIO4_LIST(_MMIO) \
	_MMIO(0xfffb, 0xbc30, 0x0000, 0x0000, GPIO4_DATAOUT) \
	_MMIO(0xfffb, 0xbc34, 0x0000, 0xffff, GPIO4_DIRECTION) \

#define SOC_OMAP_MPU_GPIO_LIST(_MMIO) \
	SOC_OMAP_MPU_GPIO1_LIST(_MMIO) \
	SOC_OMAP_MPU_GPIO2_LIST(_MMIO) \
	SOC_OMAP_MPU_GPIO3_LIST(_MMIO) \
	SOC_OMAP_MPU_GPIO4_LIST(_MMIO)

/* **** */

static int __soc_omap_mpu_gpio_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_omap_mpu_gpio_h h2gpio = param;
//	soc_omap_mpu_gpio_p gpio = *h2gpio;

	handle_free(param);

	return(0);
}

UNUSED_FN static uint __soc_omap_mpu_gpio_unit(uint32_t ppa)
{
	const uint32_t unit = (((ppa >> 13) & 2) | ((ppa >> 11) & 1)) ^ 3;

	return(unit);
}

/* **** */

static uint32_t _soc_omap_mpu_gpio_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_mpu_gpio_p gpio = param;
	const csx_p csx = gpio->csx;

	const uint8_t offset = ppa & 0xff;
	const uint8_t unit = __soc_omap_mpu_gpio_unit(ppa);

	const uint32_t data = csx_data_offset_mem_access(&gpio->data[unit], offset, size, write);

	if(_trace_mmio_mpu_gpio)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static csx_mmio_access_list_t _soc_omap_mpu_gpio_acl[] = {
	SOC_OMAP_MPU_GPIO_LIST(SOC_OMAP_MPU_GPIO_ACLE)
	{ .ppa = ~0U, },
};

int soc_omap_mpu_gpio_init(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_gpio_h h2gpio)
{
	if(_trace_init) {
		LOG();
	}

	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2gpio);

	soc_omap_mpu_gpio_p gpio = handle_calloc((void**)h2gpio, 1, sizeof(soc_omap_mpu_gpio_t));
	ERR_NULL(gpio);

	gpio->csx = csx;
	gpio->mmio = mmio;

	csx_mmio_callback_atexit(mmio, __soc_omap_mpu_gpio_atexit, h2gpio);

	// TODO: per GPIOx

//	for(int i = 0; i < 4; i++)
		csx_mmio_register_access_list(mmio, 0, _soc_omap_mpu_gpio_acl, gpio);

	return(0);
}
