#include "csx_mmio.h"

#include "config.h"

/* **** soc level includes */

#include "soc_omap_cfg.h"
#include "soc_omap_dma.h"
#include "soc_omap_dpll.h"
#include "soc_omap_gp_timer.h"
#include "soc_omap_lcd.h"
#include "soc_omap_misc.h"
#include "soc_omap_mpu.h"
#include "soc_omap_mpu_gpio.h"
#include "soc_omap_mpu_ihr.h"
#include "soc_omap_mpu_mmc.h"
#include "soc_omap_mpu_timer.h"
#include "soc_omap_os_timer.h"
#include "soc_omap_tc.h"
#include "soc_omap_uart.h"
#include "soc_omap_usb.h"
#include "soc_omap_watchdog.h"

/* **** csx level includes */

#include "csx_data.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** local library level includes */

#include "libbse/include/action.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/unused.h"

/* **** system level includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

typedef struct csx_mmio_mem_access_tag* csx_mmio_mem_access_ptr;
typedef csx_mmio_mem_access_ptr const csx_mmio_mem_access_ref;

typedef struct csx_mmio_mem_access_tag {
	armvm_mem_fn fn;
	void* param;
	const char* name;
	csx_mmio_access_list_ptr acle;
}csx_mmio_mem_access_t;

typedef struct csx_mmio_tag {
	union {
		csx_mmio_mem_access_t mem_access[CSX_MMIO_ALLOC];
		uint64_t padding[2];
	};

	soc_omap_cfg_ptr cfg;
	soc_omap_dma_ptr dma;
	soc_omap_dpll_ptr dpll;
	soc_omap_gp_timer_ptr gp_timer;
	soc_omap_lcd_ptr lcd;
	soc_omap_misc_ptr misc;
	soc_omap_mpu_ptr mpu;
	soc_omap_mpu_gpio_ptr mpu_gpio;
	soc_omap_mpu_ihr_ptr mpu_ihr;
	soc_omap_mpu_mmc_ptr mpu_mmc;
	soc_omap_mpu_timer_ptr mpu_timer;
	soc_omap_os_timer_ptr os_timer;
	soc_omap_tc_ptr tc;
	soc_omap_uart_ptr uart;
	soc_omap_usb_ptr usb;
	soc_omap_watchdog_ptr wdt;
//
	csx_ptr csx;
}csx_mmio_t;

/* **** */

static csx_mmio_mem_access_ptr __csx_mmio_mem_access(csx_mmio_ref mmio, const uint32_t ppa) {
	return(&mmio->mem_access[ppa - TIPB_MMIO_START]);
}

static csx_mmio_mem_access_ptr __csx_mmio_register_access(csx_mmio_ref mmio, const uint32_t ppa, armvm_mem_fn const fn, void *const param)
{
	csx_mmio_mem_access_ref cmmap = __csx_mmio_mem_access(mmio, ppa);

	cmmap->fn = fn;
	cmmap->param = param;

	return(cmmap);
}

/* **** */

static uint32_t _csx_mmio_mem_access(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	assert(0 != param);

	csx_mmio_ref mmio = param;

	csx_mmio_mem_access_ref cmmap = __csx_mmio_mem_access(mmio, ppa);
	uint32_t data = write ? *write : 0;

	if(cmmap->fn)
		return(cmmap->fn(cmmap->param, ppa, size, write));

	if(cmmap->param)
		return(0);

	csx_mmio_trace_mem_access(mmio->csx, ppa, size, write, data);

//	LOG_ACTION(exit(-1));

	return(0);
}

/* **** */

void csx_mmio_access_list_reset(csx_mmio_ref mmio, csx_mmio_access_list_ref acl, const size_t size, void *const data)
{
	for(csx_mmio_access_list_ptr acle = acl; ~0U != acle->ppa; acle++)
	{
		const uint32_t offset = acle->ppa & 0xff;

		csx_data_offset_write(data, offset, size, acle->reset_value);
	}

	UNUSED(mmio);
}

/* **** */

static
int csx_mmio_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int csx_mmio_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	csx_mmio_ref mmio = param;
	csx_ref csx = mmio->csx;
	ERR_NULL(csx);

	/* **** */

	armvm_mem_mmap_cb(csx->armvm->mem, TIPB_MMIO_START, TIPB_MMIO_END, _csx_mmio_mem_access, mmio);

	/* **** */

	return(err);
}

static action_handler_t csx_mmio_action_sublist[] = {
	{{ .list = &soc_omap_cfg_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, cfg) },
	{{ .list = &soc_omap_dma_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, dma) },
	{{ .list = &soc_omap_dpll_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, dpll) },
	{{ .list = &soc_omap_gp_timer_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, gp_timer) },
	{{ .list = &soc_omap_lcd_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, lcd) },
	{{ .list = &soc_omap_misc_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, misc) },
	{{ .list = &soc_omap_mpu_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, mpu) },
	{{ .list = &soc_omap_mpu_gpio_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, mpu_gpio) },
	{{ .list = &soc_omap_mpu_ihr_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, mpu_ihr) },
	{{ .list = &soc_omap_mpu_mmc_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, mpu_mmc) },
	{{ .list = &soc_omap_mpu_timer_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, mpu_timer) },
	{{ .list = &soc_omap_os_timer_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, os_timer) },
	{{ .list = &soc_omap_tc_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, tc) },
	{{ .list = &soc_omap_uart_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, uart) },
	{{ .list = &soc_omap_usb_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, usb) },
	{{ .list = &soc_omap_watchdog_action_list }, { .dereference = 1, .is_list = 1 }, offsetof(csx_mmio_t, wdt) },
	{{0}, { 0 }, 0 },
};

action_list_t csx_mmio_action_list = {
	.list = {
		[_ACTION_EXIT] = {{ csx_mmio_action_exit }, { 0 }, 0 },
		[_ACTION_INIT] = {{ csx_mmio_action_init }, { 0 }, 0 },
	},

	.sublist = csx_mmio_action_sublist
};

/* **** */

csx_mmio_ptr csx_mmio_alloc(csx_ref csx, csx_mmio_href h2mmio)
{
	ERR_NULL(csx);
	ERR_NULL(h2mmio);

	ACTION_LOG(alloc);

	/* **** */

	csx_mmio_ref mmio = handle_calloc(h2mmio, 1, sizeof(csx_mmio_t));
	ERR_NULL(mmio);

	mmio->csx = csx;

	/* **** */

	ERR_NULL(soc_omap_cfg_alloc(csx, mmio, &mmio->cfg));
	ERR_NULL(soc_omap_dma_alloc(csx, mmio, &mmio->dma));
	ERR_NULL(soc_omap_dpll_alloc(csx, mmio, &mmio->dpll));
	ERR_NULL(soc_omap_gp_timer_alloc(csx, mmio, &mmio->gp_timer));
	ERR_NULL(soc_omap_lcd_alloc(csx, mmio, &mmio->lcd));
	ERR_NULL(soc_omap_misc_alloc(csx, mmio, &mmio->misc));
	ERR_NULL(soc_omap_mpu_alloc(csx, mmio, &mmio->mpu));
	ERR_NULL(soc_omap_mpu_gpio_alloc(csx, mmio, &mmio->mpu_gpio));
	ERR_NULL(soc_omap_mpu_ihr_alloc(csx, mmio, &mmio->mpu_ihr));
	ERR_NULL(soc_omap_mpu_mmc_alloc(csx, mmio, &mmio->mpu_mmc));
	ERR_NULL(soc_omap_mpu_timer_alloc(csx, mmio, &mmio->mpu_timer));
	ERR_NULL(soc_omap_os_timer_alloc(csx, mmio, &mmio->os_timer));
	ERR_NULL(soc_omap_tc_alloc(csx, mmio, &mmio->tc));
	ERR_NULL(soc_omap_uart_alloc(csx, mmio, &mmio->uart));
	ERR_NULL(soc_omap_usb_alloc(csx, mmio, &mmio->usb));
	ERR_NULL(soc_omap_watchdog_alloc(csx, mmio, &mmio->wdt));

	/* **** */

	return(mmio);
}

void csx_mmio_register_access(csx_mmio_ref mmio, const uint32_t ppa, armvm_mem_fn const fn, void *const param)
{
	if(_trace_mmio) {
		LOG("ppa 0x%08x, param = 0x%08" PRIxPTR, ppa, (uintptr_t)param);
	}

	__csx_mmio_register_access(mmio, ppa, fn, param);
}

void csx_mmio_register_access_list(csx_mmio_ref mmio, const uint32_t ppa_base, csx_mmio_access_list_ref acl, void *const param)
{
	assert(0 != acl);
	assert(0 != mmio);

	for(csx_mmio_access_list_ptr acle = acl; ~0U != acle->ppa; acle++)
	{
		const uint32_t ppa = ppa_base + acle->ppa;

		if(_trace_mmio) {
			LOG("ppa (0x%08x + 0x%08x) = 0x%08x, param = 0x%08" PRIxPTR " -- %s",
				ppa_base, acle->ppa, ppa, (uintptr_t)param, acle->name ? acle->name : "");
		}

		csx_mmio_mem_access_ref cmmap = __csx_mmio_register_access(mmio,
			ppa, acle->fn, param);

		cmmap->name = acle->name;
	}
}

void csx_mmio_trace_mem_access(csx_ref csx, const uint32_t ppa, const size_t size, uint32_t *const write, const uint32_t read)
{
	assert(0 != csx);

	if(write) {
		CSX_MMIO_TRACE_WRITE(csx, ppa, size, *write);
	} else {
		CSX_MMIO_TRACE_READ(csx, ppa, size, read);
	}
}
