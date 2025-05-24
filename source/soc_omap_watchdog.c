#include "soc_omap_watchdog.h"

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */

#include "libbse/include/action.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** system includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

typedef struct soc_omap_watchdog_tag {
	uint32_t cntl;
	uint32_t load;
	uint32_t mode;
//
	csx_ptr csx;
	csx_mmio_ptr mmio;
}soc_omap_watchdog_t;

#define SOC_OMAP_WATCHDOG_ACL(_MMIO) \
	_MMIO(0xfffe, 0xb034, 0x0000, 0x0000, WWPS, _soc_omap_watchdog_wwps) \
	_MMIO(0xfffe, 0xb048, 0x0000, 0x0000, WSPR, _soc_omap_watchdog_wspr) \
	_MMIO(0xfffe, 0xc808, 0x0000, 0x8000, MPU_WDT_TIMER_MODE, _soc_omap_watchdog_timer_mode)

enum {
	SOC_OMAP_WATCHDOG_ACL(MMIO_ENUM)
};

/* **** */

static uint32_t _soc_omap_watchdog_timer_mode(void *const param,
	const uint32_t ppa,
	const size_t size,
	uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_watchdog_ref sow = param;
	csx_ref csx = sow->csx;

	uint32_t data = write ? *write : 0;

	if(write) {
		if(_trace_mmio_watchdog) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
		}
		sow->mode = data;
	} else
		return(sow->mode);

	return(data);
}

static uint32_t _soc_omap_watchdog_wspr(void *const param,
	const uint32_t ppa,
	const size_t size,
	uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_watchdog_ref sow = param;
	csx_ref csx = sow->csx;

	uint32_t data = write ? *write : 0;

	if(_trace_mmio_watchdog)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data)

	return(data);
}

static uint32_t _soc_omap_watchdog_wwps(void *const param,
	const uint32_t ppa,
	const size_t size,
	uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_watchdog_ref sow = param;
	csx_ref csx = sow->csx;

	uint32_t data = write ? *write : 0;

	if(_trace_mmio_watchdog)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data)

	return(data);
}

/* **** */

static csx_mmio_access_list_t _soc_omap_watchdog_acl[] = {
	SOC_OMAP_WATCHDOG_ACL(MMIO_TRACE_FN)
	{ .ppa = ~0U, },
};

/* **** */

static
int soc_omap_watchdog_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int soc_omap_watchdog_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	soc_omap_watchdog_ref sow = param;

	/* **** */

	ERR_NULL(sow->mmio);
	csx_mmio_register_access_list(sow->mmio, 0, _soc_omap_watchdog_acl, sow);

	/* **** */

	return(err);
}

static
int soc_omap_watchdog_action_reset(int err, void *const param, action_ref)
{
	ACTION_LOG(reset);

	soc_omap_watchdog_ref sow = param;

	/* **** */

	sow->cntl = 0x00000e02;
	sow->load = 0x0000ffff;
	sow->mode = 0x00008000;

	/* **** */

	return(err);
}

action_list_t soc_omap_watchdog_action_list = {
	.list = {
		[_ACTION_EXIT] = { { soc_omap_watchdog_action_exit }, { 0 }, 0, },
		[_ACTION_INIT] = { { soc_omap_watchdog_action_init }, { 0 }, 0, },
		[_ACTION_RESET] = { { soc_omap_watchdog_action_reset }, { 0 }, 0, },
	}
};

soc_omap_watchdog_ptr soc_omap_watchdog_alloc(csx_ref csx,
	csx_mmio_ref mmio, soc_omap_watchdog_href h2sow)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2sow);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_watchdog_ref sow = handle_calloc(h2sow, 1, sizeof(soc_omap_watchdog_t));
	ERR_NULL(sow);

	sow->csx = csx;
	sow->mmio = mmio;

	/* **** */

	return(sow);
}
