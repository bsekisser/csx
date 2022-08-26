#include "soc_mmio_dpll.h"

#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define _DPLL(_x)			(CSX_MMIO_DPLL_BASE + (_x))

#define MMIO_LIST \
	MMIO(0xfffe, 0xcf00, 0x0000, 0x2002, 32, MEM_RW, DPLL1_CTL_REG)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

#define DPLL1_CTL_REG		_DPLL(0x000)

void soc_mmio_dpll_write(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_dpll_p dpll = param;
	const csx_p csx = dpll->csx;
	
	const ea_trace_p eat = soc_mmio_trace(csx->mmio, trace_list, addr);
	if(eat)
	{
		switch(addr)
		{
			case	DPLL1_CTL_REG:
			{
				const uint pll_enable = BEXT(value, 4);
				if(1)
				{
					LOG("LS_DISABLE: %01u, IAI: %01u, IOB: %01u, TEST: %01u",
						BEXT(value, 15), BEXT(value, 14), BEXT(value, 13),
						BEXT(value, 12));
					LOG("PLL_MULT: %02u, PLL_DIV: %01u, PLL_ENABLE: %01u",
						mlBFEXT(value, 11, 7), mlBFEXT(value, 6, 5), pll_enable);
					LOG("BYPASS_DIV: %01u, BREAKLN: %01u, LOCK: %01u",
						 mlBFEXT(value, 3, 2), BEXT(value, 1), BEXT(value, 0));
				}
				value |= pll_enable;
			}	break;
		}

		soc_data_write(data + (addr & 0xff), value, size);
	} else {
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

static soc_mmio_peripheral_t dpll_peripheral = {
	.base = CSX_MMIO_DPLL_BASE,
	.trace_list = trace_list,

	.write = soc_mmio_dpll_write,
};


int soc_mmio_dpll_init(csx_p csx, soc_mmio_p mmio, soc_mmio_dpll_h h2dpll)
{
	soc_mmio_dpll_p dpll = calloc(1, sizeof(soc_mmio_dpll_t));
	
	ERR_NULL(dpll);
	if(!dpll)
		return(-1);

	dpll->csx = csx;
	dpll->mmio = mmio;
	
	*h2dpll = dpll;
	
	soc_mmio_peripheral(mmio, &dpll_peripheral, dpll);
	
	return(0);
}
