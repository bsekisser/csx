#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_cfg.h"
#include "csx_mmio_dpll.h"
#include "csx_mmio_mpu.h"
#include "csx_mmio_mpu_gpio.h"
#include "csx_mmio_ocp.h"
#include "csx_mmio_timer.h"
#include "csx_mmio_watchdog.h"

#include "page.h"

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

typedef struct csx_mmio_t* csx_mmio_p;
typedef struct csx_mmio_t {
	csx_p					csx;
	
	csx_mmio_cfg_p			cfg;
	csx_mmio_dpll_p			dpll;
	csx_mmio_mpu_p			mpu;
	csx_mmio_mpu_gpio_p		mpu_gpio[4];
	csx_mmio_ocp_p			ocp;
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

void csx_mmio_trace_reset(csx_mmio_p mmio, ea_trace_p tl, uint8_t* dst)
{
	for(int i = 0; i < 0xff; i++)
		dst[i] = 0;

	int i = 0;
	do {
		ea_trace_p tle = &tl[i++];

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		uint32_t value = tle->reset_value;
		if(value)
			csx_data_write(&dst[tle->address & 0xff], value, tle->size);
	}while(tl[i].address);
}


uint32_t csx_mmio_read(csx_mmio_p mmio, uint32_t vaddr, uint8_t size)
{
	uint32_t module = vaddr & _BF(31, 8);

	switch(module)
	{
		case	CSX_MMIO_CFG_BASE + 0x000:
		case	CSX_MMIO_CFG_BASE + 0x100:
			return(csx_mmio_cfg_read(mmio->cfg, vaddr, size));
			break;
		case	CSX_MMIO_DPLL_BASE:
			return(csx_mmio_dpll_read(mmio->dpll, vaddr, size));
			break;
		case	CSX_MMIO_MPU_BASE:
			return(csx_mmio_mpu_read(mmio->mpu, vaddr, size));
			break;
		case	CSX_MMIO_MPU_GPIO1_BASE:
			return(csx_mmio_mpu_gpio_read(mmio->mpu_gpio[0], vaddr, size));
			break;
		case	CSX_MMIO_MPU_GPIO2_BASE:
			return(csx_mmio_mpu_gpio_read(mmio->mpu_gpio[1], vaddr, size));
			break;
		case	CSX_MMIO_MPU_GPIO3_BASE:
			return(csx_mmio_mpu_gpio_read(mmio->mpu_gpio[2], vaddr, size));
			break;
		case	CSX_MMIO_MPU_GPIO4_BASE:
			return(csx_mmio_mpu_gpio_read(mmio->mpu_gpio[3], vaddr, size));
			break;
		case	CSX_MMIO_OCP_BASE:
			return(csx_mmio_ocp_read(mmio->ocp, vaddr, size));
			break;
		case	CSX_MMIO_TIMER(2):
			return(csx_mmio_timer_read(mmio->timer[(vaddr >> 8) & 0x03], vaddr, size));
			break;
		case	CSX_MMIO_WATCHDOG_BASE:
		case	CSX_MMIO_TIMER_WDT_BASE:
			return(csx_mmio_watchdog_read(mmio->wdt, vaddr, size));
			break;
		/* **** */
	}

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
	
	LOG("vaddr = 0x%08x, module = 0x%08x", vaddr, module);
	LOG_ACTION(exit(1));
	return(0);
}

void csx_mmio_write(csx_mmio_p mmio, uint32_t vaddr, uint32_t value, uint8_t size)
{
	uint32_t module = vaddr & _BF(31, 8);

	switch(module)
	{
		case	CSX_MMIO_CFG_BASE + 0x000:
		case	CSX_MMIO_CFG_BASE + 0x100:
			return(csx_mmio_cfg_write(mmio->cfg, vaddr, value, size));
			break;
		case	CSX_MMIO_DPLL_BASE:
			return(csx_mmio_dpll_write(mmio->dpll, vaddr, value, size));
			break;
		case	CSX_MMIO_MPU_BASE:
			return(csx_mmio_mpu_write(mmio->mpu, vaddr, value, size));
			break;
		case	CSX_MMIO_MPU_GPIO1_BASE:
			return(csx_mmio_mpu_gpio_write(mmio->mpu_gpio[0], vaddr, value, size));
			break;
		case	CSX_MMIO_MPU_GPIO2_BASE:
			return(csx_mmio_mpu_gpio_write(mmio->mpu_gpio[1], vaddr, value, size));
			break;
		case	CSX_MMIO_MPU_GPIO3_BASE:
			return(csx_mmio_mpu_gpio_write(mmio->mpu_gpio[2], vaddr, value, size));
			break;
		case	CSX_MMIO_MPU_GPIO4_BASE:
			return(csx_mmio_mpu_gpio_write(mmio->mpu_gpio[3], vaddr, value, size));
			break;
		case	CSX_MMIO_OCP_BASE:
			return(csx_mmio_ocp_write(mmio->ocp, vaddr, value, size));
			break;
		case	CSX_MMIO_TIMER(2):
			return(csx_mmio_timer_write(mmio->timer[(vaddr >> 8) & 0x03], vaddr, value, size));
			break;
		case	CSX_MMIO_WATCHDOG_BASE:
		case	CSX_MMIO_TIMER_WDT_BASE:
			return(csx_mmio_watchdog_write(mmio->wdt, vaddr, value, size));
			break;
	}

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
	csx_mmio_cfg_reset(mmio->cfg);
	csx_mmio_dpll_reset(mmio->dpll);
	csx_mmio_mpu_reset(mmio->mpu);
	csx_mmio_mpu_gpio_reset(mmio->mpu_gpio[0]);
	csx_mmio_mpu_gpio_reset(mmio->mpu_gpio[1]);
	csx_mmio_mpu_gpio_reset(mmio->mpu_gpio[2]);
	csx_mmio_mpu_gpio_reset(mmio->mpu_gpio[3]);
	csx_mmio_ocp_reset(mmio->ocp);
	csx_mmio_timer_reset(mmio->timer[0]);
	csx_mmio_timer_reset(mmio->timer[1]);
	csx_mmio_timer_reset(mmio->timer[2]);
	csx_mmio_watchdog_reset(mmio->wdt);

	csx_data_write(&mmio->upld[0x08], 0x00008000, sizeof(uint32_t));
}

int csx_mmio_init(csx_p csx, csx_mmio_h h2mmio)
{
	int err;
	csx_mmio_p mmio;
	
	ERR_NULL(mmio = malloc(sizeof(csx_mmio_t)));
	if(!mmio)
		return(-1);

	mmio->csx = csx;
	*h2mmio = mmio;
	
	ERR(err = csx_mmio_cfg_init(csx, mmio, &mmio->cfg));
	ERR(err = csx_mmio_dpll_init(csx, mmio, &mmio->dpll));
	ERR(err = csx_mmio_mpu_init(csx, mmio, &mmio->mpu));
	ERR(err = csx_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[0]));
	ERR(err = csx_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[1]));
	ERR(err = csx_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[2]));
	ERR(err = csx_mmio_mpu_gpio_init(csx, mmio, &mmio->mpu_gpio[3]));
	ERR(err = csx_mmio_ocp_init(csx, mmio, &mmio->ocp));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[0]));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[1]));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[2]));
	ERR(err = csx_mmio_watchdog_init(csx, mmio, &mmio->wdt));

	return(err);
}
