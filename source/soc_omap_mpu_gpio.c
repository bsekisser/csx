#include "config.h"
#include "soc_omap_mpu_gpio.h"

/* **** */

#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx_data.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"
#include "libbse/include/bitfield.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** */

#include <assert.h>
#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_gpio_unit_tag* soc_omap_mpu_gpio_unit_ptr;
typedef soc_omap_mpu_gpio_unit_ptr const soc_omap_mpu_gpio_unit_ref;

typedef struct soc_omap_mpu_gpio_unit_tag {
	uint32_t clear_dataout;
	uint32_t datain;
	uint32_t dataout;
	uint32_t direction;
	uint32_t edge_control2;
	uint32_t irqenable1;
	uint32_t set_dataout;
	uint32_t sysconfig;
	uint32_t xxxx_xxc0;
}soc_omap_mpu_gpio_unit_t;

typedef struct soc_omap_mpu_gpio_tag {
	soc_omap_mpu_gpio_unit_t unit[4];
//
	csx_ptr csx;
	csx_mmio_ptr mmio;
}soc_omap_mpu_gpio_t;

/* **** */

static soc_omap_mpu_gpio_unit_ptr __soc_omap_mpu_gpio_unit(
	soc_omap_mpu_gpio_ref gpio, const uint32_t ppa)
{
	const uint32_t unit = (((ppa >> 13) & 2) | ((ppa >> 11) & 1)) ^ 3;

	return(&gpio->unit[unit]);
}

/* **** */

#define SOC_OMAP_MPU_GPIO_VAR(_x) \
	static uint32_t _soc_omap_mpu_gpio_##_x(void *const param, \
		const uint32_t ppa, const size_t size, uint32_t *const write) \
	{ \
		if(_check_pedantic_mmio_size) { \
			assert((sizeof(uint32_t) | sizeof(uint16_t)) & size); \
		} \
	\
		soc_omap_mpu_gpio_ref gpio = param; \
		csx_ref csx = gpio->csx; \
	\
		soc_omap_mpu_gpio_unit_ref unit = __soc_omap_mpu_gpio_unit(gpio, ppa); \
	\
		csx_data_target_t target = { \
			.base = &unit->_x, \
			.offset = 0, \
			.size = sizeof(unit->_x), \
		}; \
	\
		const uint32_t data = csx_data_target_mem_access(&target, size, write);	\
	\
		if(_trace_mmio_mpu_gpio) \
			CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data); \
	\
		return(data); \
	}


SOC_OMAP_MPU_GPIO_VAR(clear_dataout)
SOC_OMAP_MPU_GPIO_VAR(datain)
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
	GPIO_ACLE(0x2c, DATAIN, _soc_omap_mpu_gpio_datain)
	GPIO_ACLE(0x30, DATAOUT, _soc_omap_mpu_gpio_dataout)
	GPIO_ACLE(0x34, DIRECTION, _soc_omap_mpu_gpio_direction)
	GPIO_ACLE(0x3c, EDGE_CTRL2, _soc_omap_mpu_gpio_edge_control2)
	GPIO_ACLE(0xb0, CLEAR_DATAOUT, _soc_omap_mpu_gpio_clear_dataout)
	GPIO_ACLE(0xc0, xxxx_xxc0, _soc_omap_mpu_gpio_xxxx_xxc0)
	GPIO_ACLE(0xf0, SET_DATAOUT, _soc_omap_mpu_gpio_set_dataout)
	{ .ppa = ~0U, },
};

/* **** */

static
int soc_omap_mpu_gpio_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int soc_omap_mpu_gpio_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	soc_omap_mpu_gpio_ref gpio = param;

	/* **** */

	csx_mmio_ref mmio = gpio->mmio;
	ERR_NULL(mmio);

	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_GPIO1, __soc_omap_mpu_gpio_acl, gpio);
	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_GPIO2, __soc_omap_mpu_gpio_acl, gpio);
	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_GPIO3, __soc_omap_mpu_gpio_acl, gpio);
	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_GPIO4, __soc_omap_mpu_gpio_acl, gpio);

	/* **** */

	return(err);
}

static
int soc_omap_mpu_gpio_action_reset(int err, void *const param, action_ref)
{
	ACTION_LOG(reset);

	soc_omap_mpu_gpio_ref gpio = param;

	/* **** */

	for(unsigned i = 0; i < 4; i++) {
		soc_omap_mpu_gpio_unit_ref unit = &gpio->unit[i];

		memset(unit, 0, sizeof(soc_omap_mpu_gpio_unit_t));

		unit->direction = 0x0000ffff;
	}

	/* **** */

	return(err);
}

action_list_t soc_omap_mpu_gpio_action_list = {
	.list = {
		[_ACTION_EXIT] = {{ soc_omap_mpu_gpio_action_exit }, { 0 }, 0 },
		[_ACTION_INIT] = {{ soc_omap_mpu_gpio_action_init }, { 0 }, 0 },
		[_ACTION_RESET] = {{ soc_omap_mpu_gpio_action_reset }, { 0 }, 0 },
	}
};

/* **** */

soc_omap_mpu_gpio_ptr soc_omap_mpu_gpio_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_gpio_href h2gpio)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2gpio);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_mpu_gpio_ref gpio = handle_calloc(h2gpio, 1, sizeof(soc_omap_mpu_gpio_t));
	ERR_NULL(gpio);

	gpio->csx = csx;
	gpio->mmio = mmio;

	/* **** */

	return(gpio);
}
