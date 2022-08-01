#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_dpll.h"

#define _DPLL(_x)			(CSX_MMIO_DPLL_BASE + (_x))

#define MMIO_LIST \
	MMIO(0xfffe, 0xcf00, 0x0000, 0x2002, 32, MEM_RW, DPLL1_CTL_REG)

#include "csx_mmio_trace.h"

#define DPLL1_CTL_REG		_DPLL(0x000)

static uint32_t csx_mmio_dpll_read(void* data, uint32_t addr, uint8_t size)
{
	const csx_mmio_dpll_p dpll = data;
	const csx_p csx = dpll->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value;
	
	switch(addr)
	{
		case	DPLL1_CTL_REG:
			value = dpll->ctl_reg[0];
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
//	return(csx_data_read((uint8_t*)&value, size));
	return(value);
}

void csx_mmio_dpll_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const csx_mmio_dpll_p dpll = data;
	const csx_p csx = dpll->csx;
	
	csx_mmio_trace(csx->mmio, trace_list, addr);

	switch(addr)
	{
		case	DPLL1_CTL_REG:
		{
			int pll_enable = BEXT(value, 4);
			if(1)
			{
				LOG("LS_DISABLE: %01u, IAI: %01u, IOB: %01u, TEST: %01u",
					BEXT(value, 15), BEXT(value, 14), BEXT(value, 13),
					BEXT(value, 12));
				LOG("PLL_MULT: %02u, PLL_DIV: %01u, PLL_ENABLE: %01u",
					_MLBFX(value, 11, 7), _MLBFX(value, 6, 5), pll_enable);
				LOG("BYPASS_DIV: %01u, BREAKLN: %01u, LOCK: %01u",
					 _MLBFX(value, 3, 2), BEXT(value, 1), BEXT(value, 0));
			}
//			dpll->ctl_reg[0] = value | 1;
			dpll->ctl_reg[0] = value | pll_enable;
		}	break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;	
	}
}

void csx_mmio_dpll_reset(void* data)
{
	const csx_mmio_dpll_p dpll = data;

	dpll->ctl_reg[0] = 0x00002002;	/* 1 */
}

static csx_mmio_peripheral_t dpll_peripheral = {
	.base = CSX_MMIO_DPLL_BASE,

	.reset = csx_mmio_dpll_reset,

	.read = csx_mmio_dpll_read,
	.write = csx_mmio_dpll_write,
};


int csx_mmio_dpll_init(csx_p csx, csx_mmio_p mmio, csx_mmio_dpll_h h2dpll)
{
	csx_mmio_dpll_p dpll;
	
	ERR_NULL(dpll = malloc(sizeof(csx_mmio_dpll_t)));
	if(!dpll)
		return(-1);

	dpll->csx = csx;
	dpll->mmio = mmio;
	
	*h2dpll = dpll;
	
	csx_mmio_peripheral(mmio, &dpll_peripheral, dpll);
	
	return(0);
}
