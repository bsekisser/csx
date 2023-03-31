#include "soc_omap_watchdog.h"

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */

#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

typedef struct soc_omap_watchdog_t {
	csx_p csx;
	csx_mmio_p mmio;

	uint32_t cntl;
	uint32_t load;
	uint32_t mode;
}soc_omap_watchdog_t;

#define SOC_OMAP_WATCHDOG_ACL(_MMIO) \
	_MMIO(0xfffe, 0xb034, 0x0000, 0x0000, WWPS, _soc_omap_watchdog_wwps) \
	_MMIO(0xfffe, 0xb048, 0x0000, 0x0000, WSPR, _soc_omap_watchdog_wspr) \
	_MMIO(0xfffe, 0xc808, 0x0000, 0x8000, MPU_WDT_TIMER_MODE, _soc_omap_watchdog_timer_mode)

enum {
	SOC_OMAP_WATCHDOG_ACL(MMIO_ENUM)
};

/* **** */

static int __soc_omap_watchdog_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_omap_watchdog_h h2sow = param;
//	soc_omap_watchdog_p sow = *h2sow;

	handle_free(param);

	return(0);
}

static int __soc_omap_watchdog_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	soc_omap_watchdog_p sow = param;

	sow->cntl = 0x00000e02;
	sow->load = 0x0000ffff;
	sow->mode = 0x00008000;
	
	return(0);
}

/* **** */

static uint32_t _soc_omap_watchdog_timer_mode(void* param,
	uint32_t ppa,
	size_t size,
	uint32_t* write)
{
	assert(sizeof(uint32_t) == size);

	const soc_omap_watchdog_p sow = param;

	uint32_t data = write ? *write : 0;

	if(write) {
		if(_trace_mmio_watchdog) {
			CSX_MMIO_TRACE_WRITE(sow->csx, ppa, size, data);
		}
		sow->mode = data;
	} else
		return(sow->mode);

	return(data);
}

static uint32_t _soc_omap_watchdog_wspr(void* param,
	uint32_t ppa,
	size_t size,
	uint32_t* write)
{
	assert(sizeof(uint32_t) == size);

	const soc_omap_watchdog_p sow = param;

	uint32_t data = write ? *write : 0;

	CSX_MMIO_TRACE_MEM_ACCESS(sow->csx, ppa, size, write, data)

	return(data);
}

static uint32_t _soc_omap_watchdog_wwps(void* param,
	uint32_t ppa,
	size_t size,
	uint32_t* write)
{
	assert(sizeof(uint32_t) == size);

	const soc_omap_watchdog_p sow = param;

	uint32_t data = write ? *write : 0;

	CSX_MMIO_TRACE_MEM_ACCESS(sow->csx, ppa, size, write, data)

	return(data);
}

/* **** */

static csx_mmio_access_list_t _soc_omap_watchdog_acl[] = {
	SOC_OMAP_WATCHDOG_ACL(MMIO_TRACE_FN)
	{ .ppa = ~0U, },
};

/* **** */

int soc_omap_watchdog_init(csx_p csx, csx_mmio_p mmio, soc_omap_watchdog_h h2sow)
{
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2sow);

	if(_trace_init) {
		LOG();
	}

	soc_omap_watchdog_p sow = handle_calloc((void**)h2sow, 1, sizeof(soc_omap_watchdog_t));
	ERR_NULL(sow);
	
	sow->csx = csx;
	sow->mmio = mmio;

	csx_mmio_callback_atexit(mmio, __soc_omap_watchdog_atexit, h2sow);
	csx_mmio_callback_atreset(mmio, __soc_omap_watchdog_atreset, sow);
	
	/* **** */

	csx_mmio_register_access_list(mmio, 0, _soc_omap_watchdog_acl, sow);
	
	/* **** */
	
	return(0);
}
