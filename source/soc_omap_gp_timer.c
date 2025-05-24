#include "soc_omap_gp_timer.h"

/* **** */

#include "csx_data.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "libbse/include/action.h"
#include "libbse/include/bitfield.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_gp_timer_tag {
	uint32_t tclr;
	uint32_t tiocp_cfg;
	uint32_t tier;
	uint32_t tisr;
	uint32_t tldr;
	uint32_t tmar;
	uint32_t tsicr;
	uint32_t twer;
//
	csx_ptr csx;
	csx_mmio_ptr mmio;
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

/*
 * TODO: csx_data_mem_access
 *
 * 		Operation will fail on big endian systems
 */

#define SOC_OMAP_GP_TIMER_VAR_FN(_name) \
	static uint32_t _soc_omap_gp_timer_ ## _name(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write) \
	{ \
		if(_check_pedantic_mmio_size) \
			assert(sizeof(uint32_t) == size); \
	\
		soc_omap_gp_timer_ref gpt = param; \
		csx_ref csx = gpt->csx; \
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

/* **** */

static
int soc_omap_gp_timer_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int soc_omap_gp_timer_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	soc_omap_gp_timer_ref gpt = param;

	/* **** */

	csx_mmio_ref mmio = gpt->mmio;
	ERR_NULL(mmio);

	for(unsigned i = 0; i < 8; i++)
		csx_mmio_register_access_list(mmio, SOC_OMAP_GP_TIMER_BASE(i),
			__soc_omap_gp_timer_acl, gpt);

	/* **** */

	return(err);
}

action_list_t soc_omap_gp_timer_action_list = {
	.list = {
		[_ACTION_EXIT] = {{ soc_omap_gp_timer_action_exit }, { 0 }, 0, },
		[_ACTION_INIT] = {{ soc_omap_gp_timer_action_init }, { 0 }, 0, },
	}
};

/* **** */

soc_omap_gp_timer_ptr soc_omap_gp_timer_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_gp_timer_href h2gpt)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2gpt);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_gp_timer_ref gpt = handle_calloc(h2gpt, 1, sizeof(soc_omap_gp_timer_t));
	ERR_NULL(gpt);

	gpt->csx = csx;
	gpt->mmio = mmio;

	/* **** */

	return(gpt);
}
