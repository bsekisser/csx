#include "soc_mmio.h"

#include "soc_mmio_omap.h"

#include "soc_mmio_cfg.h"
#include "soc_mmio_dpll.h"
#include "soc_mmio_mpu.h"
#include "soc_mmio_mpu_gpio.h"
#include "soc_mmio_mpu_ihr.h"
#include "soc_mmio_ocp.h"
#include "soc_mmio_gp_timer.h"
#include "soc_mmio_os_timer.h"
#include "soc_mmio_timer.h"
#include "soc_mmio_watchdog.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
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

	uint8_t					data[CSX_MMIO_SIZE];
	void*					param[0x400];
	soc_mmio_peripheral_p	peripheral[0x400];
//	soc_mmio_read_fn		read[0x400];
//	soc_mmio_write_fn		write[0x400];
//	struct {
//		void*				data;
//		void				(*fn)(void*);
//	}reset[0x64];

	soc_mmio_cfg_p			cfg;
	soc_mmio_dpll_p			dpll;
	soc_mmio_mpu_p			mpu;
	soc_mmio_mpu_gpio_p		mpu_gpio[4];
	soc_mmio_mpu_ihr_p		mpu_ihr;
	soc_mmio_ocp_p			ocp;
	soc_mmio_gp_timer_p		gp_timer;
	soc_mmio_os_timer_p		os_timer;
	soc_mmio_timer_p		timer[3];
	soc_mmio_watchdog_p		wdt;

//	soc_mmio_dsp_p			dsp;
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

static void _soc_mmio_peripheral(soc_mmio_p mmio, uint32_t va, __mpt_p p2mpt)
{
	p2mpt->mmio_data_offset = _MODULE_DATA_OFFSET(va);
	p2mpt->module = _MODULE(va);
	p2mpt->offset = va & 0xff;
	
	p2mpt->data = &mmio->data[p2mpt->mmio_data_offset];
	p2mpt->param = mmio->param[p2mpt->module];
	p2mpt->mp = mmio->peripheral[p2mpt->module];
}

ea_trace_p soc_mmio_get_trace(ea_trace_p tl, uint32_t address)
{
	if(0) LOG("tl = 0x%08x, address = 0x%08x", (uint32_t)tl, address);

	if(!tl)
		return(0);

	int i = 0;
	do {
		const ea_trace_p tle = &tl[i++];

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		if(tle->address == address)
			return(tle);
		if(0 == tle->address)
			return(0);
	}while(tl[i].address);

	return(0);
}

int soc_mmio_init(csx_p csx, soc_mmio_h h2mmio)
{
	LOG();

	int err = 0;
	soc_mmio_p mmio = calloc(1, sizeof(soc_mmio_t));

	ERR_NULL(mmio);
	if(!mmio)
		return(-1);

	mmio->csx = csx;
	*h2mmio = mmio;

	for(int i = 0; i < 0x400; i++)
	{
		mmio->data[i] = 0;
		mmio->param[i] = 0;
		mmio->peripheral[i] = 0;
	}

	ERR(err = soc_mmio_cfg_init(csx, mmio, &mmio->cfg));
	ERR(err = soc_mmio_dpll_init(csx, mmio, &mmio->dpll));
	ERR(err = soc_mmio_mpu_init(csx, mmio, &mmio->mpu));
	ERR(err = soc_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[0]));
//	ERR(err = soc_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[1]));
//	ERR(err = soc_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[2]));
//	ERR(err = soc_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[3]));
	ERR(err = soc_mmio_mpu_ihr_init(csx, mmio, &mmio->mpu_ihr));
	ERR(err = soc_mmio_ocp_init(csx, mmio, &mmio->ocp));
	ERR(err = soc_mmio_gp_timer_init(csx, mmio, &mmio->gp_timer));
	ERR(err = soc_mmio_os_timer_init(csx, mmio, &mmio->os_timer));
	ERR(err = soc_mmio_timer_init(csx, mmio, &mmio->timer[0]));
//	ERR(err = soc_mmio_timer_init(csx, mmio, &mmio->timer[1]));
//	ERR(err = soc_mmio_timer_init(csx, mmio, &mmio->timer[2]));
	ERR(err = soc_mmio_watchdog_init(csx, mmio, &mmio->wdt));

	return(err);
}

void soc_mmio_peripheral(soc_mmio_p mmio, soc_mmio_peripheral_p p, void* param)
{
	const uint16_t module = _MODULE(p->base);

	mmio->param[module] = param;
	mmio->peripheral[module] = p;

	if(1) LOG("base = 0x%08x, module = 0x%05x, param = 0x%08x, reset = 0x%08x",
		p->base, module, (uint32_t)param, (uint32_t)p->reset);
}

void soc_mmio_peripheral_reset(uint8_t* data, ea_trace_p tl)
{
	for(int i = 0; i < 256; i++)
		data[i] = 0;

	for(int i = 0;; i++)
	{
		const ea_trace_p tle = &tl[i];

		if(!trace_list[i].address)
			break;

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		const uint32_t value = tle->reset_value;
		if(value)
		{
			const uint32_t addr = tle->address;
			soc_data_write(&data[addr & 0xff], value, tle->size);
		}
	}
}

uint32_t soc_mmio_read(soc_mmio_p mmio, uint32_t vaddr, uint8_t size)
{
	__mpt_t mpt; _soc_mmio_peripheral(mmio, vaddr, &mpt);
	const soc_mmio_peripheral_p mp = mpt.mp;

	ea_trace_p tl = mp ? mp->trace_list : trace_list;

	if(mp && mp->read)
		return(mp->read(mpt.param, mpt.data, vaddr, size));

	const ea_trace_p eat = soc_mmio_trace(mmio, tl, vaddr);
	if(eat)
	{
		uint32_t value = soc_data_read(&mpt.data[mpt.offset], size);
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
		LOG("vaddr = 0x%08x, module = 0x%05x, mp = 0x%08x, eat = 0x%08x",
			vaddr, mpt.module, (uint)mpt.mp, (uint)eat);
		LOG_ACTION(exit(1));
	}

	return(0);
}

void soc_mmio_reset(soc_mmio_p mmio)
{
	LOG();

	for(int i = 0; i < 0x400; i++)
	{
		const soc_mmio_peripheral_p mp = mmio->peripheral[i];
		
		if(!mp)
			continue;
		
		LOG("base = 0x%08x", mp->base);

		if(mp->trace_list)
			soc_mmio_trace_reset(mmio, mp->trace_list, i);

		if(mp->reset) {
			uint8_t* data = &mmio->data[i << 8];
			void* param = &mmio->param[i];
			if(0) LOG("reset->fn = 0x%08x, param = 0x%08x, data = 0x%08x",
				(uint32_t)mp->reset, (uint)param, (uint32_t)data);
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

	LOG("cycle = 0x%016llx, [0x%08x]: %s", mmio->csx->cycle, address, name);

	return(eat);
}

void soc_mmio_trace_reset(soc_mmio_p mmio, ea_trace_p tl, uint module)
{
	LOG();

	int i = 0;
	do {
		const ea_trace_p tle = &tl[i++];

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);
		
		__mpt_t mpt; _soc_mmio_peripheral(mmio, tle->address, &mpt);

		if(mpt.module != module) {
			LOG("mpt->module = 0x%08x, module = 0x%08x", mpt.module, module);
			continue;
		}

		if(1) LOG("tle = 0x%08x, module = 0x%08x, offset = 0x%03x, name = %s",
			(uint32_t)tle, mpt.module, mpt.offset, tle->name);
		soc_data_write(&mpt.data[mpt.offset], tle->reset_value, tle->size);
	}while(tl[i].address);
}

void soc_mmio_write(soc_mmio_p mmio, uint32_t vaddr, uint32_t value, uint8_t size)
{
	__mpt_t mpt; _soc_mmio_peripheral(mmio, vaddr, &mpt);
	const soc_mmio_peripheral_p mp = mpt.mp;

	ea_trace_p tl = mp ? mp->trace_list : trace_list;
	
	if(mp && mp->write)
		return(mp->write(mpt.param, mpt.data, vaddr, value, size));

	const ea_trace_p eat = soc_mmio_trace(mmio, tl, vaddr);
	LOG("write -- 0x%08x", value);

	if(eat)
	{
		switch(vaddr)
		{
		}
		
		soc_data_write(&mpt.data[mpt.offset], value, size);
	} else {
		LOG("vaddr = 0x%08x, module = 0x%08x", vaddr, mpt.module);
		LOG_ACTION(exit(1));
	}
}
