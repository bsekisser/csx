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
	
	callback_list_p	atexit_list;
	callback_list_p atreset_list;
	
	soc_omap_cfg_p cfg;
	soc_omap_dpll_p dpll;
	soc_omap_gp_timer_p gp_timer;
	soc_omap_misc_p misc;
	soc_omap_mpu_p mpu;
	soc_omap_mpu_gpio_p mpu_gpio;
	soc_omap_mpu_ihr_p mpu_ihr;
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
	if(_trace_atexit)
		LOG();

	csx_mmio_h h2mmio = param;
	csx_mmio_p mmio = *h2mmio;

	callback_list_process(mmio->atexit_list);

	handle_free(&mmio->atexit_list);
	handle_free(&mmio->atreset_list);
	
	handle_free(param);
	return(0);
}

static int _csx_mmio_atreset(void* param) {
	if(_trace_atreset)
		LOG();

	csx_mmio_p mmio = param;

	callback_list_process(mmio->atreset_list);

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

DECL_CALLBACK_P_REGISTER_FN(csx_mmio, csx_mmio_p, mmio, atexit)
DECL_CALLBACK_P_REGISTER_FN(csx_mmio, csx_mmio_p, mmio, atreset)

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

int csx_mmio_init(csx_p csx, csx_mmio_h h2mmio)
{
	if(_trace_init)
		LOG();

	assert(0 != csx);
	assert(0 != h2mmio);
	
	csx_mmio_p taclet = 0;
	
	LOG("padding = 0x%08zx, mem_access[x] = 0x%08zx", 
		sizeof(taclet->padding), sizeof(taclet->mem_access[0]));

	assert(sizeof(taclet->padding) >= sizeof(taclet->mem_access[0]));

	csx_mmio_p mmio = handle_calloc((void**)h2mmio, 1, sizeof(csx_mmio_t));
	ERR_NULL(mmio);

	/* **** */

	mmio->csx = csx;

	csx_callback_atexit(csx, _csx_mmio_atexit, h2mmio);
	csx_callback_atreset(csx, _csx_mmio_atreset, mmio);

	callback_list_alloc_init(&mmio->atexit_list, 32, LIST_LIFO);
	callback_list_alloc_init(&mmio->atreset_list, 32, LIST_FIFO);

	csx_mem_mmap(csx, TIPB_MMIO_START, TIPB_MMIO_END, csx_mmio_mem_access, mmio);

	/* **** */

	soc_omap_cfg_init(csx, mmio, &mmio->cfg);
	soc_omap_dpll_init(csx, mmio, &mmio->dpll);
	soc_omap_gp_timer_init(csx, mmio, &mmio->gp_timer);
	soc_omap_misc_init(csx, mmio, &mmio->misc);
	soc_omap_mpu_init(csx, mmio, &mmio->mpu);
	soc_omap_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio);
	soc_omap_mpu_ihr_init(csx, mmio, &mmio->mpu_ihr);
	soc_omap_mpu_timer_init(csx, mmio, &mmio->mpu_timer);
	soc_omap_os_timer_init(csx, mmio, &mmio->os_timer);
	soc_omap_tc_init(csx, mmio, &mmio->tc);
	soc_omap_uart_init(csx, mmio, &mmio->uart);
	soc_omap_usb_init(csx, mmio, &mmio->usb);
	soc_omap_watchdog_init(csx, mmio, &mmio->wdt);

	/* **** */

	return(0);
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
