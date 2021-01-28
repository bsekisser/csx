#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_cfg.h"
#include "csx_mmio_dpll.h"
#include "csx_mmio_mpu.h"
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
	csx_mmio_ocp_p			ocp;
	csx_mmio_timer_p		timer[3];
	csx_mmio_watchdog_p		wdt;

	uint8_t					upld[_BV(8)];
	uint32_t				usb_clnt_syscon1;
}csx_mmio_t;

ea_trace_p csx_mmio_trace(csx_mmio_p mmio, ea_trace_p tl, uint32_t address)
{
	ea_trace_p eat = csx_mmio_get_trace(tl, address);
	const char *name = eat ? eat->name : "";

	LOG("cycle = 0x%016llx, [0x%08x]: %s", mmio->csx->cycle, address, name);
	
	return(eat);
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
	}

	csx_mmio_trace(mmio, trace_list, vaddr);

	switch(vaddr)
	{
//		case	CSX_MMIO_UPLD_BASE:
//			return(csx_data_read(&mmio->upld[vaddr & _BM(8)], size));
//			break;
		case	USB_CLNT_SYSCON1:
			return(mmio->usb_clnt_syscon1);
			break;
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

	csx_mmio_trace(mmio, trace_list, vaddr);

	switch(vaddr)
	{
//		case	CSX_MMIO_UPLD_BASE:
//			return(csx_data_write(&mmio->upld[vaddr & _BM(8)], value, size));
//			break;
		case	USB_CLNT_SYSCON1:
			mmio->usb_clnt_syscon1 = value;
			return;
			break;
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
	ERR(err = csx_mmio_ocp_init(csx, mmio, &mmio->ocp));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[0]));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[1]));
	ERR(err = csx_mmio_timer_init(csx, mmio, &mmio->timer[2]));
	ERR(err = csx_mmio_watchdog_init(csx, mmio, &mmio->wdt));

	return(err);
}
