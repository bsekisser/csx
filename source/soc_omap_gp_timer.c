#include "soc_omap_gp_timer.h"

/* **** */

#include "csx_data.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "bitfield.h"
#include "callback_qlist.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_gp_timer_t {
	csx_p csx;
	csx_mmio_p mmio;

	uint32_t tclr;
	uint32_t tiocp_cfg;
	uint32_t tier;
	uint32_t tisr;
	uint32_t tldr;
	uint32_t tmar;
	uint32_t tsicr;
	uint32_t twer;

	callback_qlist_elem_t atexit;
}soc_omap_gp_timer_t;

/* **** */

enum {
	_TIOCP_CFG =	0x10,
	_TISR =			0x18,
	_TIER =			0x1c,
	_TWER =			0x20,
	_TCLR =			0x24,
	_TLDR =			0x2c,
	_TMAR =			0x38,
	_TSICR =		0x40,
};

#define SOC_OMAP_GP_TIMER_BASE(_x) (SOC_OMAP_GP_TIMER + ((_x) * 0x0800))

/* **** */

static int __soc_omap_gp_timer_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_omap_gp_timer_h h2gpt = param;
//	soc_omap_gp_timer_p gpt = *h2gpt;

	handle_free(param);

	return(0);
}

/* **** */

/*
 * TODO: csx_data_mem_access
 *
 * 		Operation will fail on big endian systems
 */

#define SOC_OMAP_GP_TIMER_VAR_FN(_name) \
	static uint32_t _soc_omap_gp_timer_ ## _name(void* param, uint32_t ppa, size_t size, uint32_t* write) \
	{ \
		if(_check_pedantic_mmio_size) \
			assert(sizeof(uint32_t) == size); \
	\
		const soc_omap_gp_timer_p gpt = param; \
		const csx_p csx = gpt->csx; \
	\
		csx_data_target_t target = { \
			.base = &gpt->_name, \
			.offset = 0, \
			.size = sizeof(gpt->_name), \
		}; \
	\
		const uint32_t data = csx_data_target_mem_access(&target, size, write); \
	\
		if(_trace_mmio_gp_timer) \
			CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data); \
	\
		return(data); \
	}

SOC_OMAP_GP_TIMER_VAR_FN(tclr)
SOC_OMAP_GP_TIMER_VAR_FN(tiocp_cfg)
SOC_OMAP_GP_TIMER_VAR_FN(tier)
SOC_OMAP_GP_TIMER_VAR_FN(tisr)
SOC_OMAP_GP_TIMER_VAR_FN(tldr)
SOC_OMAP_GP_TIMER_VAR_FN(tmar)
SOC_OMAP_GP_TIMER_VAR_FN(tsicr)
SOC_OMAP_GP_TIMER_VAR_FN(twer)

/* **** */

static csx_mmio_access_list_t __soc_omap_gp_timer_acl[] = {
	MMIO_TRACE_FN(0, _TCLR, 0, 0, TCLR, _soc_omap_gp_timer_tclr)
	MMIO_TRACE_FN(0, _TIOCP_CFG, 0, 0, TIOCP_CFG, _soc_omap_gp_timer_tiocp_cfg)
	MMIO_TRACE_FN(0, _TIER, 0, 0, TIER, _soc_omap_gp_timer_tier)
	MMIO_TRACE_FN(0, _TISR, 0, 0, TISR, _soc_omap_gp_timer_tisr)
	MMIO_TRACE_FN(0, _TLDR, 0, 0, TLDR, _soc_omap_gp_timer_tldr)
	MMIO_TRACE_FN(0, _TMAR, 0, 0, TMAR, _soc_omap_gp_timer_tmar)
	MMIO_TRACE_FN(0, _TSICR, 0, 0, TSICR, _soc_omap_gp_timer_tsicr)
	MMIO_TRACE_FN(0, _TWER, 0, 0, TWER, _soc_omap_gp_timer_twer)
	{ .ppa = ~0U, },
};

soc_omap_gp_timer_p soc_omap_gp_timer_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_gp_timer_h h2gpt)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2gpt);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_omap_gp_timer_p gpt = handle_calloc((void**)h2gpt, 1, sizeof(soc_omap_gp_timer_t));
	ERR_NULL(gpt);

	gpt->csx = csx;
	gpt->mmio = mmio;

	csx_mmio_callback_atexit(mmio, &gpt->atexit, __soc_omap_gp_timer_atexit, h2gpt);

	/* **** */

	return(gpt);
}

void soc_omap_gp_timer_init(soc_omap_gp_timer_p gpt)
{
	ERR_NULL(gpt);
	
	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_mmio_p mmio = gpt->mmio;

	for(unsigned i = 0; i < 8; i++)
		csx_mmio_register_access_list(mmio, SOC_OMAP_GP_TIMER_BASE(i),
			__soc_omap_gp_timer_acl, gpt);
}
