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
	MMIO(0xfffe, 0x0104, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x0104) \
	MMIO(0xfffe, 0x0204, 0x0000, 0x0000, 32, MEM_RW, x0xfffe_0x0204)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

ea_trace_p soc_mmio_get_trace(ea_trace_p tl, uint32_t address)
{
	if(0) LOG("tl = 0x%08x, address = 0x%08x", (uint32_t)tl, address);

	if(!tl)
		return(0);

	int i = 0;
	do {
		ea_trace_p tle = &tl[i++];

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		if(tle->address == address)
			return(tle);
		if(0 == tle->address)
			return(0);
	}while(tl[i].address);

	return(0);
}

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

ea_trace_p soc_mmio_trace(soc_mmio_p mmio, ea_trace_p tl, uint32_t address)
{
	ea_trace_p eat = soc_mmio_get_trace(tl, address);
	const char *name = eat ? eat->name : "";

	LOG("cycle = 0x%016llx, [0x%08x]: %s", mmio->csx->cycle, address, name);

	return(eat);
}

void soc_mmio_trace_reset(soc_mmio_p mmio, ea_trace_p tl, uint8_t* dst, uint32_t base_mask)
{
	LOG();

	for(int i = 0; i < 0xff; i++)
		dst[i] = 0;

	int i = 0;
	do {
		ea_trace_p tle = &tl[i++];

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		uint32_t value = tle->reset_value;
		uint32_t module = tle->address & mlBF(31, 8);
		uint32_t offset = tle->address & 0xff;

		if(base_mask && (base_mask != module))
			continue;

		if(value)
		{
			if(0) LOG("tle = 0x%08x, module = 0x%08x, offset = 0x%03x, name = %s",
				(uint32_t)tle, module, offset, tle->name);
			soc_data_write(&dst[offset], value, tle->size);
		}
	}while(tl[i].address);
}


uint32_t soc_mmio_read(soc_mmio_p mmio, uint32_t vaddr, uint8_t size)
{
	const uint16_t module = ((vaddr - CSX_MMIO_BASE) >> 8) & 0x3ff;
	const uint16_t offset = vaddr & 0xff;
	
	uint8_t* data = &mmio->data[module << 8];
	const void* param = mmio->param[module];
	const soc_mmio_peripheral_p mp = mmio->peripheral[module];

	ea_trace_p tl = trace_list;

	if(mp)
	{
		if(mp->read)
			return(mp->read((void*)param, data, vaddr, size));

		tl = mp->trace_list;
	}

	ea_trace_p eat = soc_mmio_trace(mmio, tl, vaddr);
	if(eat)
	{
		switch(vaddr)
		{
			case	USB_CLNT_SYSCON1:
			default:
				return(soc_data_read(&data[offset], size));
				break;
		}
	}

	LOG("vaddr = 0x%08x, module = 0x%05x", vaddr, module);
	LOG_ACTION(exit(1));
	return(0);
}

void soc_mmio_write(soc_mmio_p mmio, uint32_t vaddr, uint32_t value, uint8_t size)
{
	const uint16_t module = ((vaddr - CSX_MMIO_BASE) >> 8) & 0x3ff;
	const uint16_t offset = vaddr & 0xff;
	
	uint8_t* data = &mmio->data[module << 8];
	const void* param = mmio->param[module];
	const soc_mmio_peripheral_p mp = mmio->peripheral[module];

	ea_trace_p tl = trace_list;
	
	if(mp)
	{
		if(mp->write)
			return(mp->write((void*)param, data, vaddr, value, size));
		
		tl = mp->trace_list;
	}

	ea_trace_p eat = soc_mmio_trace(mmio, tl, vaddr);
	if(eat)
	{
		switch(vaddr)
		{
			case	USB_CLNT_SYSCON1:
			default:
				return(soc_data_write(&data[offset], value, size));
				break;
		}
	}

	LOG("vaddr = 0x%08x, module = 0x%08x", vaddr, module);
	LOG_ACTION(exit(1));
	return;
}

void soc_mmio_reset(soc_mmio_p mmio)
{
	LOG();

	for(int i = 0; i < 0x400; i++)
	{
		soc_mmio_peripheral_p mp = mmio->peripheral[i];
		
		if(!mp || !mp->reset)
			continue;
		
		void (*fn)(void* param, void* data);
		
		fn = mp->reset;
		if(fn) {
			uint8_t* data = &mmio->data[i << 8];
			void* param = &mmio->param[i];
			if(0) LOG("reset->fn = 0x%08x, param = 0x%08x, data = 0x%08x", (uint32_t)fn, (uint)param, (uint32_t)data);
			fn(param, data);
		}
	}
}

/*
	uint32_t soc_mmio_peripheral_read(uint32_t addr, void* data, ea_trace_p tl)
	{
		return(soc_data_read(&data[addr & 0xff], data, size);
	}
*/

void soc_mmio_peripheral_reset(uint8_t* data, ea_trace_p tl)
{
	for(int i = 0; i < 256; i++)
		data[i] = 0;

	for(int i = 0;; i++)
	{
		ea_trace_p tle = &tl[i];

		if(!trace_list[i].address)
			break;

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		uint32_t value = tle->reset_value;
		if(value)
		{
			uint32_t addr = tle->address;
			soc_data_write(&data[addr & 0xff], value, tle->size);
		}
	}
}

/*	void soc_mmio_peripheral_write(
		uint32_t addr,
		uint32_t value,
		void* data,
		ea_trace_p tl)
	{
		soc_data_write(data[addr & 0xff], value, size);
	}
*/

void soc_mmio_peripheral(soc_mmio_p mmio, soc_mmio_peripheral_p p, void* param)
{
	const uint16_t module = ((p->base - CSX_MMIO_BASE) >> 8) & 0x3ff;

	mmio->param[module] = param;
	mmio->peripheral[module] = p;

	if(0) LOG("base = 0x%08x, module = 0x%05x, param = 0x%08x, reset = 0x%08x",
		p->base, module, (uint32_t)param, (uint32_t)p->reset);
}

int soc_mmio_init(csx_p csx, soc_mmio_h h2mmio)
{
	LOG();

	int err;
	soc_mmio_p mmio;

	ERR_NULL(mmio = malloc(sizeof(soc_mmio_t)));
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
