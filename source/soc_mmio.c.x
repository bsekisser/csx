#include "config.h"
#include "soc_mmio.h"

#include "csx_data.h"
#include "csx_statistics.h"
#include "soc_mmio_omap.h"

#include "soc_mmio_cfg.h"
#include "soc_mmio_dpll.h"
#include "soc_mmio_mpu.h"
#include "soc_mmio_mpu_gpio.h"
#include "soc_mmio_mpu_ihr.h"
#include "soc_mmio_mpu_mmc.h"
#include "soc_mmio_ocp.h"
#include "soc_mmio_gp_timer.h"
#include "soc_mmio_os_timer.h"
#include "soc_mmio_uart.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"
//#include "page.h"
//#include "queue.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define MMIO_LIST \
	MMIO(0xfffb, 0x4018, 0x0000, 0x0000, 16, MEM_RW, USB_CLNT_SYSCON1) \
	MMIO(0xfffe, 0x6010, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x6010) \
	MMIO(0xfffe, 0x6014, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x6014) \
	MMIO(0xfffe, 0x6018, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x6018) \
	MMIO(0xfffe, 0x601c, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x601c) \
	MMIO(0xfffe, 0x6020, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x6020) \
	MMIO(0xfffe, 0x6030, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x6030) \
	MMIO(0xfffe, 0x6034, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x6034)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

#define _MODULE_DATA_OFFSET(_x) \
	((_x) - CSX_MMIO_BASE)

#define _MODULE(_x) \
	((_MODULE_DATA_OFFSET(_x) >> 8) & 0x3ff)

typedef void (*void_fn_p)(void*);

typedef struct soc_mmio_t* soc_mmio_p;
typedef struct soc_mmio_t {
	csx_p					csx;

//	uint8_t					data[CSX_MMIO_SIZE];
	uint8_t*				data;
	void*					param[0x400];
	soc_mmio_peripheral_p	peripheral[0x400];

	soc_mmio_cfg_p			cfg;
	soc_mmio_dpll_p			dpll;
	soc_mmio_mpu_p			mpu;
	soc_mmio_mpu_gpio_p		mpu_gpio;
	soc_mmio_mpu_ihr_p		mpu_ihr;
	soc_mmio_mpu_mmc_p		mpu_mmc;
	soc_mmio_ocp_p			ocp;
	soc_mmio_gp_timer_p		gp_timer;
	soc_mmio_os_timer_p		os_timer;
	soc_mmio_uart_p			uart;

	callback_list_t			atexit_list;
	callback_list_t			atreset_list;
}soc_mmio_t;

typedef struct __mpt_t* __mpt_p;
typedef struct __mpt_t {
	uint8_t* data;
	uint16_t module;
	uint32_t mmio_data_offset;
	soc_mmio_peripheral_p mp;
	void* param;
	uint16_t offset;
}__mpt_t;

static int _soc_mmio_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	soc_mmio_h h2mmio = param;
	soc_mmio_p mmio = *h2mmio;
	
	callback_list_process(&mmio->atexit_list);
	
	handle_free(param);
	
	return(0);
}

static void _soc_mmio_peripheral(soc_mmio_p mmio, uint32_t va, __mpt_p p2mpt)
{
	p2mpt->mmio_data_offset = _MODULE_DATA_OFFSET(va);
	p2mpt->module = _MODULE(va);
	p2mpt->offset = va & 0xff;

	p2mpt->data = &mmio->data[p2mpt->mmio_data_offset];
	p2mpt->param = mmio->param[p2mpt->module];
	p2mpt->mp = mmio->peripheral[p2mpt->module];

	if(p2mpt->mp) {
		if(0) LOG("param = 0x%08" PRIxPTR ", data = 0x%08" PRIxPTR ", va = 0x%08x, module = 0x%05x",
			(uintptr_t)p2mpt->param, (uintptr_t)p2mpt->data, va, p2mpt->module);

		if(_check_pedantic_mmio) {
			assert(0 != p2mpt->data);
			assert(0 != p2mpt->param);
		}
	}
}

static uint32_t _soc_mmio_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(write)
		soc_mmio_write(param, ppa, size, *write);
	else
		return(soc_mmio_read(param, ppa, size));
	
	return(0);
}

static int _soc_mmio_reset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	soc_mmio_p mmio = param;

	soc_mmio_reset(mmio);

	callback_list_process(&mmio->atreset_list);

	return(0);
}


/* **** */

DECL_CALLBACK_REGISTER_FN(soc_mmio, soc_mmio_p, mmio, atexit)
DECL_CALLBACK_REGISTER_FN(soc_mmio, soc_mmio_p, mmio, atreset)

ea_trace_p soc_mmio_get_trace(ea_trace_p tl, uint32_t address)
{
	if(0) LOG("tl = 0x%08" PRIxPTR ", address = 0x%08x", (uintptr_t)tl, address);

	if(!tl)
		return(0);

	int i = 0;
	do {
		const ea_trace_p tle = &tl[i++];

		if(0) LOG("tle = 0x%08" PRIxPTR ", name = %s", (uintptr_t)tle, tle->name);

		if(tle->address == address)
			return(tle);
		if(0 == tle->address)
			return(0);
	}while(tl[i].address);

	return(0);
}

int soc_mmio_init(csx_p csx, soc_mmio_h h2mmio, void* mmio_data)
{
	if(_trace_init) {
		LOG();
	}

	assert(0 != csx);
	assert(0 != h2mmio);
	
	int err = 0;

	soc_mmio_p mmio = HANDLE_CALLOC(h2mmio, 1, sizeof(soc_mmio_t));
	ERR_NULL(mmio);

	mmio->csx = csx;
	mmio->data = mmio_data;

	callback_list_init(&mmio->atexit_list, 0, LIST_LIFO);
	callback_list_init(&mmio->atreset_list, 0, LIST_FIFO);

	csx_callback_atexit(csx, _soc_mmio_atexit, h2mmio);
	csx_callback_atreset(csx, _soc_mmio_reset, mmio);

	for(int i = 0; i < 0x400; i++)
	{
		mmio->data[i] = 0;
		mmio->param[i] = 0;
		mmio->peripheral[i] = 0;
	}

	csx_mem_mmap(csx, CSX_MMIO_BASE, CSX_MMIO_STOP, _soc_mmio_mem_access, mmio);

	ERR(err = soc_mmio_cfg_init(csx, mmio, &mmio->cfg));
	ERR(err = soc_mmio_dpll_init(csx, mmio, &mmio->dpll));
	ERR(err = soc_mmio_mpu_init(csx, mmio, &mmio->mpu));
	ERR(err = soc_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio));
	ERR(err = soc_mmio_mpu_ihr_init(csx, mmio, &mmio->mpu_ihr));
	ERR(err = soc_mmio_mpu_mmc_init(csx, mmio, &mmio->mpu_mmc));
	ERR(err = soc_mmio_ocp_init(csx, mmio, &mmio->ocp));
	ERR(err = soc_mmio_gp_timer_init(csx, mmio, &mmio->gp_timer));
	ERR(err = soc_mmio_os_timer_init(csx, mmio, &mmio->os_timer));
	ERR(err = soc_mmio_uart_init(csx, mmio, &mmio->uart));
//	ERR(err = soc_mmio_watchdog_init(csx, mmio, &mmio->wdt));

	return(err);
}

void soc_mmio_peripheral(soc_mmio_p mmio, soc_mmio_peripheral_p p, void* param)
{
	const uint16_t module = _MODULE(p->base);

	assert(0 == mmio->param[module]);
	assert(0 == mmio->peripheral[module]);

	mmio->param[module] = param;
	mmio->peripheral[module] = p;

	if(0) LOG("base = 0x%08x, module = 0x%05x, param = 0x%08" PRIxPTR ", reset = 0x%08" PRIxPTR,
		p->base, module, (uintptr_t)param, (uintptr_t)p->reset);
}

void soc_mmio_peripheral_reset(soc_mmio_p mmio, soc_mmio_peripheral_p mp)
{
	__mpt_t mpt; _soc_mmio_peripheral(mmio, mp->base, &mpt);

	for(int i = 0; i < 256; i++)
		mpt.data[i] = 0;

	for(int i = 0;; i++)
	{
		const ea_trace_p tle = &mp->trace_list[i];

		if(!tle->address)
			break;

		if(0) LOG("tle = 0x%08" PRIxPTR ", name = %s", (uintptr_t)tle, tle->name);

		const uint32_t value = tle->reset_value;
		if(value)
		{
			const uint32_t addr = tle->address;
			csx_data_offset_write(mpt.data, addr & 0xff, tle->size, value);
		}
	}

	if(mp->reset)
		mp->reset(mpt.param, mpt.data, mp);
}

uint32_t soc_mmio_read(soc_mmio_p mmio, uint32_t vaddr, size_t size)
{
	CSX_COUNTER_INC(mmio.read);

	csx_p csx = mmio->csx;

	if(csx_mmio_has_callback_read(csx, vaddr))
		return(csx_mmio_read(csx, vaddr, size));

	__mpt_t mpt; _soc_mmio_peripheral(mmio, vaddr, &mpt);
	const soc_mmio_peripheral_p mp = mpt.mp;

	ea_trace_p tl = mp ? mp->trace_list : trace_list;

	assert(0 != ((mpt.offset + size) & 0xff));

	if(mp && mp->read) {
		if(_check_pedantic_mmio) {
			assert(0 != mpt.data);
			assert(0 != mpt.param);
		}

		return(mp->read(mpt.param, mpt.data, vaddr, size));
	}

	const ea_trace_p eat = soc_mmio_trace(mmio, tl, vaddr);
	if(eat)
	{
		uint32_t value = csx_data_offset_read(mpt.data, mpt.offset, size);
		switch(vaddr)
		{
			case	x0xfffe_0x6014:
				value |= 1;
				break;
			case	x0xfffe_0x6018:
				value |= 1;
				break;
		}

		return(value);
	} else {
		LOG("vaddr = 0x%08x, module = 0x%05x, mp = 0x%08" PRIxPTR ", eat = 0x%08" PRIxPTR,
			vaddr, mpt.module, (uintptr_t)mp, (uintptr_t)eat);
		LOG_ACTION(exit(1));
	}

	return(0);
}

void soc_mmio_reset(soc_mmio_p mmio)
{
	for(int i = 0; i < 0x400; i++)
	{
		if(!mmio->param[0x3cb]) {
			LOG("0x%05x", i);
			LOG_ACTION(exit(-1));
		}

		const soc_mmio_peripheral_p mp = mmio->peripheral[i];

		if(!mp)
			continue;

		if(0) LOG("base = 0x%08x", mp->base);

		if(mp->trace_list)
			soc_mmio_trace_reset(mmio, mp->trace_list, i);

		if(mp->reset) {
			uint8_t* data = &mmio->data[i << 8];
			void* param = mmio->param[i];
			if(0) LOG("reset->fn = 0x%08" PRIxPTR ", param = 0x%08" PRIxPTR ", data = 0x%08" PRIxPTR,
				(uintptr_t)mp->reset, (uintptr_t)param, (uintptr_t)data);
			mp->reset(param, data, mp);
		}
	}
}

ea_trace_p soc_mmio_trace(soc_mmio_p mmio, ea_trace_p tl, uint32_t address)
{
	if(!tl) {
		__mpt_t mpt; _soc_mmio_peripheral(mmio, address, &mpt);
		tl = mpt.mp->trace_list;
	}

	const ea_trace_p eat = soc_mmio_get_trace(tl, address);
	const char *name = eat ? eat->name : "";

	if(_trace_mmio)
		LOG("cycle = 0x%016" PRIx64 ", [0x%08x]: %s", mmio->csx->cycle, address, name);

	return(eat);
}

void soc_mmio_trace_reset(soc_mmio_p mmio, ea_trace_p tl, uint module)
{
	int i = 0;
	do {
		const ea_trace_p tle = &tl[i++];

		if(0) LOG("tle = 0x%08" PRIxPTR ", name = %s", (uintptr_t)tle, tle->name);

		__mpt_t mpt; _soc_mmio_peripheral(mmio, tle->address, &mpt);

		if(mpt.module != module) {
			if(0) LOG("mpt->module = 0x%08x, module = 0x%08x", mpt.module, module);
			continue;
		}

		if(0) LOG("tle = 0x%08" PRIxPTR ", module = 0x%08x, offset = 0x%03x, name = %s",
			(uintptr_t)tle, mpt.module, mpt.offset, tle->name ? tle->name : "");
		csx_data_offset_write(mpt.data, mpt.offset, tle->size, tle->reset_value);
	}while(tl[i].address);
}

void soc_mmio_write(soc_mmio_p mmio, uint32_t vaddr, size_t size, uint32_t value)
{
	CSX_COUNTER_INC(mmio.write);

	csx_p csx = mmio->csx;

	if(csx_mmio_has_callback_write(csx, vaddr))
		return(csx_mmio_write(csx, vaddr, size, value));

	__mpt_t mpt; _soc_mmio_peripheral(mmio, vaddr, &mpt);
	const soc_mmio_peripheral_p mp = mpt.mp;

	ea_trace_p tl = mp ? mp->trace_list : trace_list;

	if(0 && mp)
		LOG("param = 0x%08" PRIxPTR ", data = 0x%08" PRIxPTR ", va = 0x%08x, module = 0x%05x",
			(uintptr_t)mpt.param, (uintptr_t)mpt.data, vaddr, mpt.module);

	assert(0 != ((mpt.offset + size) & 0xff));

	if(mp && mp->write) {
		if(_check_pedantic_mmio) {
			assert(0 != mpt.data);
			assert(0 != mpt.param);
		}

		return(mp->write(mpt.param, mpt.data, vaddr, size, value));
	}

	const ea_trace_p eat = soc_mmio_trace(mmio, tl, vaddr);
	if(_trace_mmio)
		LOG("write -- 0x%08x", value);

	if(eat)
	{
		switch(vaddr)
		{
		}

		csx_data_offset_write(mpt.data, mpt.offset, size, value);
	} else {
		LOG("vaddr = 0x%08x, module = 0x%08x", vaddr, mpt.module);
		LOG_ACTION(exit(1));
	}
}
