#include "soc_omap_dpll.h"

/* **** csx level includes */

#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** local library level includes*/

#include "libbse/include/bitfield.h"
#include "libbse/include/callback_qlist.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** system leve includes */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_dpll_tag {
	csx_ptr csx;
	csx_mmio_ptr mmio;

	uint32_t ctl_reg;

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}soc_omap_dpll_t;

/* **** */

static int __soc_omap_dpll_atexit(void *const param) {
	ACTION_LOG(exit);

	handle_free(param);
	return(0);
}

static int __soc_omap_dpll_atreset(void *const param) {
	ACTION_LOG(reset);

	soc_omap_dpll_ref dpll = param;

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

static uint32_t _soc_omap_dpll_ctl(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
//	LOG("size = 0x%08zx", size);

	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	soc_omap_dpll_ref dpll = param;
	csx_ref csx = dpll->csx;

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
	MMIO_TRACE_FN(0xfffe, 0xcf00, 0x0000, 0x2002, DPLL1_CTL_REG, _soc_omap_dpll_ctl)
	{ .ppa = ~0U, },
};

soc_omap_dpll_ptr soc_omap_dpll_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_dpll_href h2dpll)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2dpll);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_dpll_ref dpll = handle_calloc((void**)h2dpll, 1, sizeof(soc_omap_dpll_t));
	ERR_NULL(dpll);

	dpll->csx = csx;
	dpll->mmio = mmio;

	/* **** */

	csx_mmio_callback_atexit(mmio, &dpll->atexit, __soc_omap_dpll_atexit, h2dpll);
	csx_mmio_callback_atreset(mmio, &dpll->atreset, __soc_omap_dpll_atreset, dpll);

	/* **** */

	return(dpll);
}

void soc_omap_dpll_init(soc_omap_dpll_ref dpll)
{
	ACTION_LOG(init);
	ERR_NULL(dpll);

	/* **** */

	csx_mmio_register_access_list(dpll->mmio, 0, _soc_omap_dpll_acl, dpll);
}
