#include "csx_mmio.h"

#include "config.h"

/* **** soc level includes */

#include "soc_omap_cfg.h"
#include "soc_omap_dpll.h"
#include "soc_omap_gp_timer.h"
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
#include "csx_mem.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** local library level includes */

#include "err_test.h"
#include "handle.h"
#include "log.h"
#include "unused.h"

/* **** system level includes */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

typedef struct csx_mmio_mem_access_t* csx_mmio_mem_access_p;
typedef struct csx_mmio_mem_access_t {
	csx_mem_fn fn;
	void* param;
	const char* name;
	csx_mmio_access_list_p acle;
}csx_mmio_mem_access_t;

typedef struct csx_mmio_t {
	union {
		csx_mmio_mem_access_t mem_access[CSX_MMIO_ALLOC];
		uint64_t padding[2];
	};

	csx_p csx;
	
	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atexit;
	
	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atreset;
	
	soc_omap_cfg_p cfg;
	soc_omap_dpll_p dpll;
	soc_omap_gp_timer_p gp_timer;
	soc_omap_misc_p misc;
	soc_omap_mpu_p mpu;
	soc_omap_mpu_gpio_p mpu_gpio;
	soc_omap_mpu_ihr_p mpu_ihr;
	soc_omap_mpu_mmc_p mpu_mmc;
	soc_omap_mpu_timer_p mpu_timer;
	soc_omap_os_timer_p os_timer;
	soc_omap_tc_p tc;
	soc_omap_uart_p uart;
	soc_omap_usb_p usb;
	soc_omap_watchdog_p wdt;
}csx_mmio_t;

/* **** */

static csx_mmio_mem_access_p __csx_mmio_mem_access(csx_mmio_p mmio, uint32_t ppa) {
	return(&mmio->mem_access[ppa - TIPB_MMIO_START]);
}

static csx_mmio_mem_access_p __csx_mmio_register_access(csx_mmio_p mmio, uint32_t ppa, csx_mem_fn fn, void* param)
{
	csx_mmio_mem_access_p cmmap = __csx_mmio_mem_access(mmio, ppa);
	
	cmmap->fn = fn;
	cmmap->param = param;
	
	return(cmmap);
}

/* **** */

static int _csx_mmio_atexit(void* param) {
	if(_trace_atexit) {
		LOG(">>");
	}

	const csx_mmio_h h2mmio = param;
	const csx_mmio_p mmio = *h2mmio;

	callback_qlist_process(&mmio->atexit.list);

	if(_trace_atexit_pedantic) {
		LOG("--");
	}

	handle_free(param);

	if(_trace_atexit_pedantic) {
		LOG("<<");
	}

	return(0);
}

static int _csx_mmio_atreset(void* param) {
	if(_trace_atreset)
		LOG();

	const csx_mmio_p mmio = param;

	callback_qlist_process(&mmio->atreset.list);

	return(0);
}

/* **** */

void csx_mmio_access_list_reset(csx_mmio_p mmio, csx_mmio_access_list_p acl, size_t size, void* data)
{
	do {
		csx_mmio_access_list_p acle = acl++;
		const uint32_t offset = acle->ppa & 0xff;

		csx_data_offset_write(data, offset, size, acle->reset_value);
	}while(~0U != acl->ppa);

	UNUSED(mmio);
}

csx_mmio_p csx_mmio_alloc(csx_p csx, csx_mmio_h h2mmio)
{
	ERR_NULL(csx);
	ERR_NULL(h2mmio);

	if(_trace_alloc) {
		LOG();
	}

	const csx_mmio_p mmio = HANDLE_CALLOC(h2mmio, 1, sizeof(csx_mmio_t));
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
	ERR_NULL(soc_omap_dpll_alloc(csx, mmio, &mmio->dpll));
	ERR_NULL(soc_omap_gp_timer_alloc(csx, mmio, &mmio->gp_timer));
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

void csx_mmio_callback_atexit(csx_mmio_p mmio,
	callback_qlist_elem_p cble, callback_fn fn, void* param)
{
	if(0) {
		LOG_START("cbl: 0x%08" PRIxPTR, (uintptr_t)&mmio->atexit.list);
		_LOG_(", cble: 0x%08" PRIxPTR, (uintptr_t)cble);
		_LOG_(", fn: 0x%08" PRIxPTR, (uintptr_t)fn);
		LOG_END(", param: 0x%08" PRIxPTR, (uintptr_t)param);
	}

	callback_qlist_setup_and_register_callback(&mmio->atexit.list, cble, fn, param);
}

void csx_mmio_callback_atreset(csx_mmio_p mmio,
	callback_qlist_elem_p cble, callback_fn fn, void* param)
{
	if(0) {
		LOG_START("cbl: 0x%08" PRIxPTR, (uintptr_t)&mmio->atreset.list);
		_LOG_(", cble: 0x%08" PRIxPTR, (uintptr_t)cble);
		_LOG_(", fn: 0x%08" PRIxPTR, (uintptr_t)fn);
		LOG_END(", param: 0x%08" PRIxPTR, (uintptr_t)param);
	}

	callback_qlist_setup_and_register_callback(&mmio->atreset.list, cble, fn, param);
}

static uint32_t csx_mmio_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	assert(0 != param);
	
	csx_mmio_p mmio = param;

	csx_mmio_mem_access_p cmmap = __csx_mmio_mem_access(mmio, ppa);
	uint32_t data = write ? *write : 0;
	
	if(cmmap->fn)
		return(cmmap->fn(cmmap->param, ppa, size, write));

	if(cmmap->param)
		return(0);

	csx_mmio_trace_mem_access(mmio->csx, ppa, size, write, data);

	LOG_ACTION(exit(-1));

	return(0);
}

void csx_mmio_init(csx_mmio_p mmio)
{
	ERR_NULL(mmio);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_mem_mmap(mmio->csx, TIPB_MMIO_START, TIPB_MMIO_END, csx_mmio_mem_access, mmio);

	/* **** */

	soc_omap_cfg_init(mmio->cfg);
	soc_omap_dpll_init(mmio->dpll);
	soc_omap_gp_timer_init(mmio->gp_timer);
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

void csx_mmio_register_access(csx_mmio_p mmio, uint32_t ppa, csx_mem_fn fn, void* param)
{
	if(_trace_mmio) {
		LOG("ppa 0x%08x, param = 0x%08" PRIxPTR, ppa, (uintptr_t)param);
	}

	__csx_mmio_register_access(mmio, ppa, fn, param);
}

void csx_mmio_register_access_list(csx_mmio_p mmio, uint32_t ppa_base, csx_mmio_access_list_p acl, void* param)
{
	assert(0 != acl);
	assert(0 != mmio);
	
	do {
		csx_mmio_access_list_p acle = acl++;

		uint32_t ppa = ppa_base + acle->ppa;

		if(_trace_mmio) {
			LOG("ppa (0x%08x + 0x%08x) = 0x%08x, param = 0x%08" PRIxPTR " -- %s",
				ppa_base, acle->ppa, ppa, (uintptr_t)param, acle->name ? acle->name : "");
		}

		csx_mmio_mem_access_p cmmap = __csx_mmio_register_access(mmio,
			ppa, acle->fn, param);

		cmmap->name = acle->name;
	}while(~0U != acl->ppa);
}

void csx_mmio_trace_mem_access(csx_p csx, uint32_t ppa, size_t size, uint32_t* write, uint32_t read)
{
	assert(0 != csx);
	
	if(write) {
		CSX_MMIO_TRACE_WRITE(csx, ppa, size, *write);
	} else {
		CSX_MMIO_TRACE_READ(csx, ppa, size, read);
	}
}
