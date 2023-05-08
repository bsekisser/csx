#include "soc_omap_dpll.h"

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** local library level includes*/

#include "bitfield.h"
#include "callback_list.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** system leve includes */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_dpll_t {
	csx_p csx;
	csx_mmio_p mmio;

	uint32_t ctl_reg;
}soc_omap_dpll_t;

/* **** */

static int _soc_omap_dpll_atexit(void* param) {
	if(_trace_atexit)
		LOG();

	handle_free(param);
	return(0);
}

static int _soc_omap_dpll_atreset(void* param) {
	if(_trace_atreset)
		LOG();

	soc_omap_dpll_p dpll = param;

	/* **** */

	dpll->ctl_reg = 0x00002002;

	/* **** */

	return(0);

	UNUSED(param);
}

enum {
	DPLL1_CTL_REG = 0x00,
};

enum {
	DPLL1_CTL_LOCK = 0x00,
	DPLL1_CTL_PLL_ENABLE = 0x04,
};

static uint32_t soc_omap_dpll_ctl(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
//	LOG("size = 0x%08zx", size);

	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	soc_omap_dpll_p dpll = param;

	uint32_t data = write ? *write : 0;

	if(write) {
		const unsigned pll_enable = BEXT(data, DPLL1_CTL_PLL_ENABLE);
		BSET_AS(dpll->ctl_reg, DPLL1_CTL_LOCK, pll_enable);

		if(_trace_mmio_dpll) {
			CSX_MMIO_TRACE_WRITE(dpll->csx, ppa, size, data);
			LOG_START("LS_DISABLE: %01u", BEXT(data, 15));
			_LOG_(", IAI: %01u", BEXT(data, 14));
			_LOG_(", IOB: %01u", BEXT(data, 13));
			LOG_END(", TEST: %01u", BEXT(data, 12));
			LOG_START("PLL_MULT: %02u", mlBFEXT(data, 11, 7));
			_LOG_(", PLL_DIV: %01u", mlBFEXT(data, 6, 5));
			LOG_END(", PLL_ENABLE: %01u", pll_enable);
			LOG_START("BYPASS_DIV: %01u", mlBFEXT(data, 3, 2));
			_LOG_(", BREAKLN: %01u", BEXT(data, 1));
			LOG_END(", LOCK: %01u", BEXT(data, 0));
		}
	} else
		data = dpll->ctl_reg;

	return(data);

	UNUSED(ppa);
}

static csx_mmio_access_list_t _soc_omap_dpll_acl[] = {
	MMIO_TRACE_FN(0xfffe, 0xcf00, 0x0000, 0x2002, DPLL1_CTL_REG, soc_omap_dpll_ctl)
	{ .ppa = ~0U, },
};

int soc_omap_dpll_init(csx_p csx, csx_mmio_p mmio, soc_omap_dpll_h h2dpll)
{
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2dpll);

	if(_trace_init)
		LOG();

	soc_omap_dpll_p dpll = handle_calloc((void**)h2dpll, 1, sizeof(soc_omap_dpll_t));
	ERR_NULL(dpll);

	dpll->csx = csx;
	dpll->mmio = mmio;

	csx_mmio_callback_atexit(mmio, _soc_omap_dpll_atexit, h2dpll);
	csx_mmio_callback_atreset(mmio, _soc_omap_dpll_atreset, dpll);

	/* **** */

	csx_mmio_register_access_list(mmio, 0, _soc_omap_dpll_acl, dpll);

	/* **** */

	return(0);
}
