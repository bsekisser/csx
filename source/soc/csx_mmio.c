#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_cfg.h"
#include "csx_mmio_dpll.h"
#include "csx_mmio_mpu.h"
#include "csx_mmio_mpu_gpio.h"
#include "csx_mmio_ocp.h"
#include "csx_mmio_os_timer.h"
#include "csx_mmio_timer.h"
#include "csx_mmio_watchdog.h"

#include "page.h"
#include "queue.h"

#define MMIO_LIST \
	MMIO(0xfffb, 0x4018, 0x0000, 0x0000, 16, MEM_RW, USB_CLNT_SYSCON1)

#include "csx_mmio_trace.h"

ea_trace_p csx_mmio_get_trace(ea_trace_p tl, uint32_t address)
{
	if(0) LOG("tl = 0x%08x, address = 0x%08x", (uint32_t)tl, address);

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

typedef struct csx_mmio_t* csx_mmio_p;
typedef struct csx_mmio_t {
	csx_p					csx;

	void*					data[0x400];
	csx_mmio_read_fn		read[0x400];
	csx_mmio_write_fn		write[0x400];
	struct {
		void*				data;
		void				(*fn)(void*);
	}reset[0x64];
	
	csx_mmio_cfg_p			cfg;
	csx_mmio_dpll_p			dpll;
	csx_mmio_mpu_p			mpu;
	csx_mmio_mpu_gpio_p		mpu_gpio[4];
	csx_mmio_ocp_p			ocp;
	csx_mmio_os_timer_p		os_timer;
	csx_mmio_timer_p		timer[3];
	csx_mmio_watchdog_p		wdt;

//	csx_mmio_dsp_p			dsp;

	uint8_t					upld[256];
	uint8_t					usb_clnt[256];
}csx_mmio_t;

ea_trace_p csx_mmio_trace(csx_mmio_p mmio, ea_trace_p tl, uint32_t address)
{
	ea_trace_p eat = csx_mmio_get_trace(tl, address);
	const char *name = eat ? eat->name : "";

	LOG("cycle = 0x%016llx, [0x%08x]: %s", mmio->csx->cycle, address, name);
	
	return(eat);
}

void csx_mmio_trace_reset(csx_mmio_p mmio, ea_trace_p tl, uint8_t* dst, uint32_t base_mask)
{
	LOG();

	for(int i = 0; i < 0xff; i++)
		dst[i] = 0;

	int i = 0;
	do {
		ea_trace_p tle = &tl[i++];

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		uint32_t value = tle->reset_value;
		uint32_t module = tle->address & _BF(31, 8);
		uint32_t offset = tle->address & 0xff;
		
		if(base_mask && (base_mask != module))
			continue;

		if(value)
		{
			if(0) LOG("tle = 0x%08x, module = 0x%08x, offset = 0x%03x, name = %s",
				(uint32_t)tle, module, offset, tle->name);
			csx_data_write(&dst[offset], value, tle->size);
		}
	}while(tl[i].address);
}


uint32_t csx_mmio_read(csx_mmio_p mmio, uint32_t vaddr, uint8_t size)
{
	uint32_t module = vaddr & _BF(31, 8);

	switch(module)
	{
//		case	CSX_MMIO_CFG_BASE + 0x000:
//		case	CSX_MMIO_CFG_BASE + 0x100:
//			return(csx_mmio_cfg_read(mmio->cfg, vaddr, size));
//			break;
//		case	CSX_MMIO_DPLL_BASE:
//			return(csx_mmio_dpll_read(mmio->dpll, vaddr, size));
//			break;
//		case	CSX_MMIO_MPU_BASE:
//			return(csx_mmio_mpu_read(mmio->mpu, vaddr, size));
//			break;
//		case	CSX_MMIO_MPU_GPIO1_BASE:
//			return(csx_mmio_mpu_gpio_read(mmio->mpu_gpio[0], vaddr, size));
//			break;
//		case	CSX_MMIO_MPU_GPIO2_BASE:
//			return(csx_mmio_mpu_gpio_read(mmio->mpu_gpio[1], vaddr, size));
//			break;
//		case	CSX_MMIO_MPU_GPIO3_BASE:
//			return(csx_mmio_mpu_gpio_read(mmio->mpu_gpio[2], vaddr, size));
//			break;
//		case	CSX_MMIO_MPU_GPIO4_BASE:
//			return(csx_mmio_mpu_gpio_read(mmio->mpu_gpio[3], vaddr, size));
//			break;
//		case	CSX_MMIO_OCP_BASE:
//			return(csx_mmio_ocp_read(mmio->ocp, vaddr, size));
//			break;
//		case	CSX_MMIO_OS_TIMER_BASE:
//			return(csx_mmio_os_timer_read(mmio->os_timer, vaddr, size));
//			break;
		case	CSX_MMIO_TIMER(2):
			return(csx_mmio_timer_read(mmio->timer[(vaddr >> 8) & 0x03], vaddr, size));
			break;
//		case	CSX_MMIO_WATCHDOG_BASE:
//		case	CSX_MMIO_TIMER_WDT_BASE:
//			return(csx_mmio_watchdog_read(mmio->wdt, vaddr, size));
//			break;
		/* **** */
	}

	const uint16_t page = ((vaddr - CSX_MMIO_BASE) >> 8) & 0x3ff;
	const csx_mmio_read_fn fn = mmio->read[page];
	if(fn)
		return(fn(mmio->data[page], vaddr, size));

	ea_trace_p eat = csx_mmio_trace(mmio, trace_list, vaddr);
	if(eat)
	{
		uint8_t offset = vaddr & 0xff;
		switch(module)
		{
//			case	CSX_MMIO_UPLD_BASE:
//				return(csx_data_read(&mmio->upld[offset], size));
//				break;
		}
		
		switch(vaddr)
		{
			case	USB_CLNT_SYSCON1:
				return(csx_data_read(&mmio->usb_clnt[offset], size));
				break;
		}
	}
	
	LOG("vaddr = 0x%08x, module = 0x%08x, page = 0x%05x", vaddr, module, page);
	LOG_ACTION(exit(1));
	return(0);
}

void csx_mmio_write(csx_mmio_p mmio, uint32_t vaddr, uint32_t value, uint8_t size)
{
	uint32_t module = vaddr & _BF(31, 8);

	switch(module)
	{
//		case	CSX_MMIO_CFG_BASE + 0x000:
//		case	CSX_MMIO_CFG_BASE + 0x100:
//			return(csx_mmio_cfg_write(mmio->cfg, vaddr, value, size));
//			break;
//		case	CSX_MMIO_DPLL_BASE:
//			return(csx_mmio_dpll_write(mmio->dpll, vaddr, value, size));
//			break;
//		case	CSX_MMIO_MPU_BASE:
//			return(csx_mmio_mpu_write(mmio->mpu, vaddr, value, size));
//			break;
//		case	CSX_MMIO_MPU_GPIO1_BASE:
//			return(csx_mmio_mpu_gpio_write(mmio->mpu_gpio[0], vaddr, value, size));
//			break;
//		case	CSX_MMIO_MPU_GPIO2_BASE:
//			return(csx_mmio_mpu_gpio_write(mmio->mpu_gpio[1], vaddr, value, size));
//			break;
//		case	CSX_MMIO_MPU_GPIO3_BASE:
//			return(csx_mmio_mpu_gpio_write(mmio->mpu_gpio[2], vaddr, value, size));
//			break;
//		case	CSX_MMIO_MPU_GPIO4_BASE:
//			return(csx_mmio_mpu_gpio_write(mmio->mpu_gpio[3], vaddr, value, size));
//			break;
//		case	CSX_MMIO_OCP_BASE:
//			return(csx_mmio_ocp_write(mmio->ocp, vaddr, value, size));
//			break;
//		case	CSX_MMIO_OS_TIMER_BASE:
//			return(csx_mmio_os_timer_write(mmio->os_timer, vaddr, value, size));
//			break;
		case	CSX_MMIO_TIMER(2):
			return(csx_mmio_timer_write(mmio->timer[(vaddr >> 8) & 0x03], vaddr, value, size));
			break;
//		case	CSX_MMIO_WATCHDOG_BASE:
//		case	CSX_MMIO_TIMER_WDT_BASE:
//			return(csx_mmio_watchdog_write(mmio->wdt, vaddr, value, size));
//			break;
	}

	const uint16_t page = ((vaddr - CSX_MMIO_BASE) >> 8) & 0x3ff;
	const csx_mmio_write_fn fn = mmio->write[page];
	if(fn)
		return(fn(mmio->data[page], vaddr, value, size));

	ea_trace_p eat = csx_mmio_trace(mmio, trace_list, vaddr);
	if(eat)
	{
		uint8_t offset = vaddr & 0xff;
		switch(module)
		{
//			case	CSX_MMIO_UPLD_BASE:
//				return(csx_data_write(&mmio->upld[offset], value, size));
//				break;
		}
		
		switch(vaddr)
		{
			case	USB_CLNT_SYSCON1:
				return(csx_data_write(&mmio->usb_clnt[offset], value, size));
				break;
		}
	}

	LOG("vaddr = 0x%08x, module = 0x%08x", vaddr, module);
	LOG_ACTION(exit(1));
	return;
}

void csx_mmio_reset(csx_mmio_p mmio)
{
	LOG();
//	csx_mmio_cfg_reset(mmio->cfg);
//	csx_mmio_dpll_reset(mmio->dpll);
//	csx_mmio_mpu_reset(mmio->mpu);
//	csx_mmio_mpu_gpio_reset(mmio->mpu_gpio[0]);
//	csx_mmio_mpu_gpio_reset(mmio->mpu_gpio[1]);
//	csx_mmio_mpu_gpio_reset(mmio->mpu_gpio[2]);
//	csx_mmio_mpu_gpio_reset(mmio->mpu_gpio[3]);
//	csx_mmio_ocp_reset(mmio->ocp);
//	csx_mmio_os_timer_reset(mmio->os_timer);
	csx_mmio_timer_reset(mmio->timer[0]);
	csx_mmio_timer_reset(mmio->timer[1]);
	csx_mmio_timer_reset(mmio->timer[2]);
//	csx_mmio_watchdog_reset(mmio->wdt);

	csx_data_write(&mmio->upld[0x08], 0x00008000, sizeof(uint32_t));

	for(int i = 0; i < 64; i++)
	{
		void (*fn)(void*);
		
		fn = mmio->reset[i].fn;
		if(fn) {
			void* data = mmio->reset[i].data;
			if(0) LOG("reset->fn = 0x%08x, data = 0x%08x", (uint32_t)fn, (uint32_t)data);
			fn(data);
		}
	}
}

void csx_mmio_peripheral(csx_mmio_p mmio, csx_mmio_peripheral_p p, void* data)
{
	const uint16_t page = ((p->base - CSX_MMIO_BASE) >> 8) & 0x3ff;

	mmio->data[page] = data;
	mmio->read[page] = p->read;
	mmio->write[page] = p->write;
	
	if(p->reset)
	{
		for(int i = 0; i < 64; i++)
		{
			if(0 == mmio->reset[i].fn)
			{
				mmio->reset[i].data = data;
				mmio->reset[i].fn = p->reset;
				break;
			}
		}
	}
	
	if(0) LOG("base = 0x%08x, page = 0x%05x, data = 0x%08x, reset = 0x%08x",
		p->base, page, (uint32_t)data, (uint32_t)p->reset);
}

int csx_mmio_init(csx_p csx, csx_mmio_h h2mmio)
{
	LOG();
	
	int err;
	csx_mmio_p mmio;
	
	ERR_NULL(mmio = malloc(sizeof(csx_mmio_t)));
	if(!mmio)
		return(-1);

	mmio->csx = csx;
	*h2mmio = mmio;
	
	for(int i = 0; i < 0x400; i++)
	{
		mmio->data[i] = 0;
		mmio->read[i] = 0;
		mmio->write[i] = 0;
	}
	
	for(int i = 0; i < 64; i++)
	{
		mmio->reset[i].data = 0;
		mmio->reset[i].fn = 0;
	}

	ERR(err = csx_mmio_cfg_init(csx, mmio, &mmio->cfg));
	ERR(err = csx_mmio_dpll_init(csx, mmio, &mmio->dpll));
	ERR(err = csx_mmio_mpu_init(csx, mmio, &mmio->mpu));
	ERR(err = csx_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[0]));
//	ERR(err = csx_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[1]));
//	ERR(err = csx_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[2]));
//	ERR(err = csx_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[3]));
	ERR(err = csx_mmio_ocp_init(csx, mmio, &mmio->ocp));
	ERR(err = csx_mmio_os_timer_init(csx, mmio, &mmio->os_timer));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[0]));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[1]));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[2]));
	ERR(err = csx_mmio_watchdog_init(csx, mmio, &mmio->wdt));

	return(err);
}
