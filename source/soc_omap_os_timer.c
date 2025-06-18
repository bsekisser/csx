#include "soc_omap_os_timer.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** local library includes */

#include "libbse/include/action.h"
#include "libbse/include/bitfield.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** system includes */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_os_timer_tag {
	uint64_t base;
	uint32_t ctrl;

	struct {
		uint32_t cntr;
		uint32_t val;
	}tick;
//
	csx_ptr csx;
	csx_mmio_ptr mmio;
}soc_omap_os_timer_t;

/* **** */

#define SOC_OMAP_OS_TIMER_ACL(_MMIO) \
	_MMIO(0xfffb, 0x9000, 0x00ff, 0xffff, OS_TIMER_TICK_VAL, _soc_omap_os_timer_tick_val) \
	_MMIO(0xfffb, 0x9008, 0x0000, 0x0008, OS_TIMER_CTRL, _soc_omap_os_timer_ctrl)

enum {
	SOC_OMAP_OS_TIMER_ACL(MMIO_ENUM)
};

/* **** */

static uint32_t _soc_omap_os_timer_ctrl(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_os_timer_ref ost = param;
	csx_ref csx = ost->csx;

	uint32_t data = write ? *write : 0;

	if(write)
		ost->ctrl = data;
	else
		data = _BCLR(ost->ctrl, 1);

	if(_trace_mmio_os_timer)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

static uint32_t _soc_omap_os_timer_tick_val(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_os_timer_ref ost = param;
	csx_ref csx = ost->csx;

	uint32_t data = write ? *write : 0;

	if(write)
		ost->tick.val = data;
	else
		data = ost->tick.val;

	if(_trace_mmio_os_timer)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static csx_mmio_access_list_t _soc_omap_os_timer_acl[] = {
	SOC_OMAP_OS_TIMER_ACL(MMIO_TRACE_FN)
	{ .ppa = ~0U, },
};

/* **** */

static
int soc_omap_os_timer_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int soc_omap_os_timer_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	soc_omap_os_timer_ref ost = param;

	/* **** */

	ERR_NULL(ost->mmio);
	csx_mmio_register_access_list(ost->mmio, 0, _soc_omap_os_timer_acl, ost);

	/* **** */

	return(err);
}

static
int soc_omap_os_timer_action_reset(int err, void *const param, action_ref)
{
	ACTION_LOG(reset);

	soc_omap_os_timer_ref ost = param;

	/* **** */

	ost->base = 0;
	ost->ctrl = 0x00000008;
	ost->tick.cntr = 0x00ffffff;
	ost->tick.val = 0x00ffffff;

	/* **** */

	return(err);
}

static
action_linklist_t soc_omap_os_timer_action_linklist[] = {
	{ offsetof(soc_omap_os_timer_t, csx), csx },
	{ offsetof(soc_omap_os_timer_t, mmio), csx_mmio },
	{ 0, 0 },
};

ACTION_LIST(soc_omap_os_timer_action_list,
	.link = soc_omap_os_timer_action_linklist,
	.list = {
		[_ACTION_EXIT] = {{ soc_omap_os_timer_action_exit }, { 0 }, 0 },
		[_ACTION_INIT] = {{ soc_omap_os_timer_action_init }, { 0 }, 0 },
		[_ACTION_RESET] = {{ soc_omap_os_timer_action_reset }, { 0 }, 0 },
	}
);

soc_omap_os_timer_ptr soc_omap_os_timer_alloc(soc_omap_os_timer_href h2ost)
{
	ACTION_LOG(alloc);
	ERR_NULL(h2ost);

	/* **** */

	soc_omap_os_timer_ref ost = handle_calloc(h2ost, 1, sizeof(soc_omap_os_timer_t));
	ERR_NULL(ost);

	/* **** */

	return(ost);
}
