#include "config.h"
#include "soc_omap_mpu_gpio.h"

/* **** */

#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx_data.h"
#include "csx.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <assert.h>
#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_gpio_unit_t* soc_omap_mpu_gpio_unit_p;
typedef struct soc_omap_mpu_gpio_unit_t {
	uint32_t clear_dataout;
	uint32_t dataout;
	uint32_t direction;
	uint32_t edge_control2;
	uint32_t irqenable1;
	uint32_t set_dataout;
	uint32_t sysconfig;
	uint32_t xxxx_xxc0;
}soc_omap_mpu_gpio_unit_t;

typedef struct soc_omap_mpu_gpio_t {
	csx_p csx;
	csx_mmio_p mmio;
	
	soc_omap_mpu_gpio_unit_t unit[4];
}soc_omap_mpu_gpio_t;

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

static int __soc_omap_mpu_gpio_atreset(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	soc_omap_mpu_gpio_p gpio = param;

	for(unsigned i = 0; i < 4; i++) {
		soc_omap_mpu_gpio_unit_p unit = &gpio->unit[i];
		
		memset(unit, 0, sizeof(soc_omap_mpu_gpio_unit_t));
		
		unit->direction = 0x0000ffff;
	}

	return(0);
}

static soc_omap_mpu_gpio_unit_p __soc_omap_mpu_gpio_unit(
	soc_omap_mpu_gpio_p gpio, uint32_t ppa)
{
	const uint32_t unit = (((ppa >> 13) & 2) | ((ppa >> 11) & 1)) ^ 3;

	return(&gpio->unit[unit]);
}

/* **** */

#define SOC_OMAP_MPU_GPIO_VAR(_x) \
	static uint32_t _soc_omap_mpu_gpio_##_x(void* param, \
		uint32_t ppa, size_t size, uint32_t* write) \
	{ \
		if(_check_pedantic_mmio_size) \
			assert(BTST((sizeof(uint16_t) | sizeof(uint32_t)), size)); \
	\
		const soc_omap_mpu_gpio_p gpio = param; \
		const csx_p csx = gpio->csx; \
	\
		const soc_omap_mpu_gpio_unit_p unit = __soc_omap_mpu_gpio_unit(gpio, ppa); \
	\
		const uint32_t data = write ? *write : unit->_x;	\
	\
		if(write) \
			unit->_x = data; \
	\
		if(_trace_mmio_mpu_gpio) \
			CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data); \
	\
		return(data); \
	}


SOC_OMAP_MPU_GPIO_VAR(clear_dataout)
SOC_OMAP_MPU_GPIO_VAR(dataout)
SOC_OMAP_MPU_GPIO_VAR(direction)
SOC_OMAP_MPU_GPIO_VAR(edge_control2)
SOC_OMAP_MPU_GPIO_VAR(irqenable1)
SOC_OMAP_MPU_GPIO_VAR(set_dataout)
SOC_OMAP_MPU_GPIO_VAR(sysconfig)
SOC_OMAP_MPU_GPIO_VAR(xxxx_xxc0)

/* **** */

#define GPIO_ACLE(_offset, _enum, _fn) \
	MMIO_TRACE_FN(0x0000, _offset, 0x0000, 0x0000, _enum, _fn)

static csx_mmio_access_list_t __soc_omap_mpu_gpio_acl[] = {
	GPIO_ACLE(0x10, SYSCONFIG, _soc_omap_mpu_gpio_sysconfig)
	GPIO_ACLE(0x1c, IRQENABLE1, _soc_omap_mpu_gpio_irqenable1)
	GPIO_ACLE(0x30, DATAOUT, _soc_omap_mpu_gpio_dataout)
	GPIO_ACLE(0x34, DIRECTION, _soc_omap_mpu_gpio_direction)
	GPIO_ACLE(0x3c, EDGE_CTRL2, _soc_omap_mpu_gpio_edge_control2)
	GPIO_ACLE(0xb0, CLEAR_DATAOUT, _soc_omap_mpu_gpio_clear_dataout)
	GPIO_ACLE(0xc0, xxxx_xxc0, _soc_omap_mpu_gpio_xxxx_xxc0)
	GPIO_ACLE(0xf0, SET_DATAOUT, _soc_omap_mpu_gpio_set_dataout)
	{ .ppa = ~0U, },
};

int soc_omap_mpu_gpio_init(csx_p csx, csx_mmio_p mmio, soc_omap_mpu_gpio_h h2gpio)
{
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2gpio);

	if(_trace_init) {
		LOG();
	}

	soc_omap_mpu_gpio_p gpio = handle_calloc((void**)h2gpio, 1, sizeof(soc_omap_mpu_gpio_t));
	ERR_NULL(gpio);

	gpio->csx = csx;
	gpio->mmio = mmio;

	csx_mmio_callback_atexit(mmio, __soc_omap_mpu_gpio_atexit, h2gpio);
	csx_mmio_callback_atreset(mmio, __soc_omap_mpu_gpio_atreset, gpio);

	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_GPIO1, __soc_omap_mpu_gpio_acl, gpio);
	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_GPIO2, __soc_omap_mpu_gpio_acl, gpio);
	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_GPIO3, __soc_omap_mpu_gpio_acl, gpio);
	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_GPIO4, __soc_omap_mpu_gpio_acl, gpio);

	return(0);
}
