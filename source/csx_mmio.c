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

	csx_ptr csx;

	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atexit;

	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atreset;

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

static int _csx_mmio_atexit(void *const param) {
	ACTION_LOG(exit);

	csx_mmio_href h2mmio = param;
	csx_mmio_ref mmio = *h2mmio;

	callback_qlist_process(&mmio->atexit.list);

	handle_ptrfree(param);

	return(0);
}

static int _csx_mmio_atreset(void *const param) {
	ACTION_LOG(reset);

	csx_mmio_ref mmio = param;

	callback_qlist_process(&mmio->atreset.list);

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

csx_mmio_ptr csx_mmio_alloc(csx_ref csx, csx_mmio_href h2mmio)
{
	ERR_NULL(csx);
	ERR_NULL(h2mmio);

	ACTION_LOG(alloc);

	csx_mmio_ref mmio = handle_calloc(h2mmio, 1, sizeof(csx_mmio_t));
	ERR_NULL(mmio);

	mmio->csx = csx;

	/* **** */

	callback_qlist_init(&mmio->atexit.list, LIST_LIFO);
	callback_qlist_init(&mmio->atreset.list, LIST_FIFO);

	/* **** */

	csx_callback_atexit(csx, &mmio->atexit.elem, _csx_mmio_atexit, h2mmio);
	csx_callback_atreset(csx, &mmio->atreset.elem, _csx_mmio_atreset, mmio);

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

void csx_mmio_callback_atexit(csx_mmio_ref mmio,
	callback_qlist_elem_p const cble, callback_fn const fn, void *const param)
{
	if(0) {
		LOG_START("cbl: 0x%08" PRIxPTR, (uintptr_t)&mmio->atexit.list);
		_LOG_(", cble: 0x%08" PRIxPTR, (uintptr_t)cble);
		_LOG_(", fn: 0x%08" PRIxPTR, (uintptr_t)fn);
		LOG_END(", param: 0x%08" PRIxPTR, (uintptr_t)param);
	}

	callback_qlist_setup_and_register_callback(&mmio->atexit.list, cble, fn, param);
}

void csx_mmio_callback_atreset(csx_mmio_ref mmio,
	callback_qlist_elem_p const cble, callback_fn const fn, void *const param)
{
	if(0) {
		LOG_START("cbl: 0x%08" PRIxPTR, (uintptr_t)&mmio->atreset.list);
		_LOG_(", cble: 0x%08" PRIxPTR, (uintptr_t)cble);
		_LOG_(", fn: 0x%08" PRIxPTR, (uintptr_t)fn);
		LOG_END(", param: 0x%08" PRIxPTR, (uintptr_t)param);
	}

	callback_qlist_setup_and_register_callback(&mmio->atreset.list, cble, fn, param);
}

static uint32_t csx_mmio_mem_access(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
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

void csx_mmio_init(csx_mmio_ref mmio)
{
	ERR_NULL(mmio);

	ACTION_LOG(init);

	/* **** */

	armvm_mem_mmap_cb(mmio->csx->armvm->mem, TIPB_MMIO_START, TIPB_MMIO_END, csx_mmio_mem_access, mmio);

	/* **** */

	soc_omap_cfg_init(mmio->cfg);
	soc_omap_dma_init(mmio->dma);
	soc_omap_dpll_init(mmio->dpll);
	soc_omap_gp_timer_init(mmio->gp_timer);
	soc_omap_lcd_init(mmio->lcd);
	soc_omap_misc_init(mmio->misc);
	soc_omap_mpu_init(mmio->mpu);
	soc_omap_mpu_gpio_init(mmio->mpu_gpio);
	soc_omap_mpu_ihr_init(mmio->mpu_ihr);
	soc_omap_mpu_mmc_init(mmio->mpu_mmc);
	soc_omap_mpu_timer_init(mmio->mpu_timer);
	soc_omap_os_timer_init(mmio->os_timer);
	soc_omap_tc_init(mmio->tc);
	soc_omap_uart_init(mmio->uart);
	soc_omap_usb_init(mmio->usb);
	soc_omap_watchdog_init(mmio->wdt);
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
