#include "soc_omap_cfg.h"

/* **** */

#include "csx_data.h"
#include "csx_mmio.h"
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

//#define PEDANTIC(_x)
#ifndef PEDANTIC
	#define PEDANTIC(_x) _x
#endif

typedef struct soc_omap_cfg_tag {
	uint8_t data[0x0200];
	uint8_t reset;
//
	csx_ptr csx;
	csx_mmio_ptr mmio;
}soc_omap_cfg_t;

#define SOC_OMAP_CFG_ACL_LIST_ACLE(_ahi, _alo, _dhi, _dlo, _name) \
	MMIO_TRACE_FN(_ahi, _alo, _dhi, _dlo, _name, _soc_omap_cfg_mem_access)

#define SOC_OMAP_CFG_ACL_LIST_0(_acl) \
	_acl(0xfffe, 0x100c, 0x0000, 0x0000, COMP_MODE_CTRL_0) \
	_acl(0xfffe, 0x1010, 0x0000, 0x0000, FUNC_MUX_CTRL_3) \
	_acl(0xfffe, 0x1014, 0x0000, 0x0000, FUNC_MUX_CTRL_4) \
	_acl(0xfffe, 0x1018, 0x0000, 0x0000, FUNC_MUX_CTRL_5) \
	_acl(0xfffe, 0x101c, 0x0000, 0x0000, FUNC_MUX_CTRL_6) \
	_acl(0xfffe, 0x1020, 0x0000, 0x0000, FUNC_MUX_CTRL_7) \
	_acl(0xfffe, 0x1024, 0x0000, 0x0000, FUNC_MUX_CTRL_8) \
	_acl(0xfffe, 0x1028, 0x0000, 0x0000, FUNC_MUX_CTRL_9) \
	_acl(0xfffe, 0x102c, 0x0000, 0x0000, FUNC_MUX_CTRL_A) \
	_acl(0xfffe, 0x1030, 0x0000, 0x0000, FUNC_MUX_CTRL_B) \
	_acl(0xfffe, 0x1034, 0x0000, 0x0000, FUNC_MUX_CTRL_C) \
	_acl(0xfffe, 0x1038, 0x0000, 0x0000, FUNC_MUX_CTRL_D) \
	_acl(0xfffe, 0x1040, 0x0000, 0x0000, PULL_DWN_CTRL_0) \
	_acl(0xfffe, 0x1044, 0x0000, 0x0000, PULL_DWN_CTRL_1) \
	_acl(0xfffe, 0x1048, 0x0000, 0x0000, PULL_DWN_CTRL_2) \
	_acl(0xfffe, 0x104c, 0x0000, 0x0000, PULL_DWN_CTRL_3) \
	_acl(0xfffe, 0x1060, 0x0000, 0x0000, VOLTAGE_CTRL_0) \
	_acl(0xfffe, 0x1064, 0x0000, 0x0006, USB_TRANSCEIVER_CTRL) \
	_acl(0xfffe, 0x1080, 0x0000, 0x0000, MOD_CONF_CTRL_0) \
	_acl(0xfffe, 0x1090, 0x0000, 0x0000, FUNC_MUX_CTRL_E) \
	_acl(0xfffe, 0x1094, 0x0000, 0x0000, FUNC_MUX_CTRL_F) \
	_acl(0xfffe, 0x1098, 0x0000, 0x0000, FUNC_MUX_CTRL_10) \
	_acl(0xfffe, 0x109c, 0x0000, 0x0000, FUNC_MUX_CTRL_11) \
	_acl(0xfffe, 0x10a0, 0x0000, 0x0000, FUNC_MUX_CTRL_12) \
	_acl(0xfffe, 0x10ac, 0x0000, 0x0000, PULL_DWN_CTRL_4) \
	_acl(0xfffe, 0x10b4, 0x0000, 0x0000, PU_PD_SEL_0) \
	_acl(0xfffe, 0x10b8, 0x0000, 0x0000, PU_PD_SEL_1) \
	_acl(0xfffe, 0x10bc, 0x0000, 0x0000, PU_PD_SEL_2) \
	_acl(0xfffe, 0x10c0, 0x0000, 0x0000, PU_PD_SEL_3) \
	_acl(0xfffe, 0x10c4, 0x0000, 0x0000, PU_PD_SEL_4)

#define SOC_OMAP_CFG_ACL_LIST_1(_acl) \
	_acl(0xfffe, 0x1110, 0x0000, 0x0000, MOD_CONF_CTRL_1) \
	_acl(0xfffe, 0x1140, 0x0000, 0x007f, RESET_CTL) \
	_acl(0xfffe, 0x1160, 0x0000, 0x0000, x0xfffe_0x1160)

enum {
	SOC_OMAP_CFG_ACL_LIST_0(MMIO_ENUM)
	SOC_OMAP_CFG_ACL_LIST_1(MMIO_ENUM)
};

/* **** */

static csx_mmio_access_list_t _soc_omap_cfg_acl_0[];
static csx_mmio_access_list_t _soc_omap_cfg_acl_1[];

/* **** */

static uint32_t _soc_omap_cfg_mod_conf_ctrl_1(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	PEDANTIC(ERR_NULL(param));
	soc_omap_cfg_ref cfg = param;
	csx_ref csx = cfg->csx;
	PEDANTIC(ERR_NULL(csx));

	const uint16_t offset = ppa & 0x1ff;

	const uint32_t data = csx_data_offset_mem_access(cfg->data, offset, size, write);

	if(_trace_mmio_cfg)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	if(write && _trace_mmio_cfg) {
		LOG_START("CFG: Mondule Configuration Control 1\n\t");
		_LOG_("CONF_CAM_CLKMUX_R: %01u", BEXT(data, 31));
		_LOG_(", CONF_PMT_DCB_SELECT_R: %01u", mlBFEXT(data, 30, 29));
		_LOG_(", CONF_OSC1_GZ_R: %01u\n\t", BEXT(data, 28));
		_LOG_("CONF_OSC1_PWRDN_R: %01u", BEXT(data, 27));
		_LOG_(", RESERVED[26]: %01u", BEXT(data, 26));
		_LOG_(", OCP_INTERCON_GATE_EN_R: %01u\n\t", BEXT(data, 25));
		_LOG_("CONF_MMC2_CLKFB_SEL_R: %01u", BEXT(data, 24));
		_LOG_(", RESERVED[23]: %01u", BEXT(data, 23));
		_LOG_(", CONF_MCBSP3_CLK_DIS_R: %01u\n\t", BEXT(data, 22));
		_LOG_("CONF_MCBSP2_CLK_DIS_R: %01u", BEXT(data, 21));
		_LOG_(", CONF_MCBSP1_CLK_DIS_R: %01u", BEXT(data, 20));
		_LOG_(", RESERVED[19:17]: %01u\n\t", mlBFEXT(data, 19, 17));
		_LOG_("RESERVED[16]: %01u", BEXT(data, 16));
		_LOG_(", CONF_MOD_GPTIMER8_CLK_SEL_R: %1u", mlBFEXT(data, 15, 14));
		_LOG_(", CONF_MOD_GPTIMER7_CLK_SEL_R: %1u\n\t", mlBFEXT(data, 13, 12));
		_LOG_("CONF_MOD_GPTIMER6_CLK_SEL_R: %1u", mlBFEXT(data, 11, 10));
		_LOG_(", CONF_MOD_GPTIMER5_CLK_SEL_R: %1u", mlBFEXT(data, 9, 8));
		_LOG_(", CONF_MOD_GPTIMER4_CLK_SEL_R: %1u\n\t", mlBFEXT(data, 7, 6));
		_LOG_("CONF_MOD_GPTIMER3_CLK_SEL_R: %1u", mlBFEXT(data, 5, 4));
		_LOG_(", CONF_MOD_GPTIMER2_CLK_SEL_R: %1u", mlBFEXT(data, 3, 2));
		LOG_END(", CONF_MOD_GPTIMER1_CLK_SEL_R: %1u", mlBFEXT(data, 1, 0));
	}

	return(data);
}

static uint32_t _soc_omap_cfg_reset_ctl(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	PEDANTIC(ERR_NULL(param));
	soc_omap_cfg_ref cfg = param;
	csx_ref csx = cfg->csx;
	PEDANTIC(ERR_NULL(csx));

	const uint16_t offset = ppa & 0x1ff;

	const uint32_t data = csx_data_offset_mem_access(cfg->data, offset, size, write);

	if(_trace_mmio_cfg)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	if(write && _trace_mmio_cfg) {
		LOG_START("CFG: Reset Control Register\n\t");
		_LOG_("UNUSED[31:7]: 0x%03x", mlBFEXT(data, 31, 7));
		_LOG_(", CONF_RNG_IDLE_MODE: %01u", BEXT(data, 6));
		_LOG_(", CONF_CAMERAIF_RESET_R: %01u\n\t", BEXT(data, 5));
		_LOG_("CONF_UWIRE_RESET_R: %01u", BEXT(data, 4));
		_LOG_(", CONF_OSTIMER_RESET_R: %01u", BEXT(data, 3));
		_LOG_(", CONF_ARMIO_RESET_R: %01u\n\t", BEXT(data, 2));
		_LOG_("RESERVED[1]: %01u", BEXT(data, 1));
		LOG_END(", CONF_OCP_RESET_R: %01u", BEXT(data, 0));
	}

	return(data);
}

static uint32_t _soc_omap_cfg_mem_access(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	PEDANTIC(ERR_NULL(param));
	soc_omap_cfg_ref cfg = param;
	csx_ref csx = cfg->csx;
	PEDANTIC(ERR_NULL(csx));

	switch(ppa) {
		case MOD_CONF_CTRL_1:
			return(_soc_omap_cfg_mod_conf_ctrl_1(param, ppa, size, write));
		case RESET_CTL:
			return(_soc_omap_cfg_reset_ctl(param, ppa, size, write));
	}

	const uint16_t offset = ppa & 0x1ff;

	const uint32_t data = csx_data_offset_mem_access(cfg->data, offset, size, write);

	if(_trace_mmio_cfg)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static csx_mmio_access_list_t _soc_omap_cfg_acl_0[] = {
	SOC_OMAP_CFG_ACL_LIST_0(SOC_OMAP_CFG_ACL_LIST_ACLE)
	{ .ppa = ~0U, }
};

static csx_mmio_access_list_t _soc_omap_cfg_acl_1[] = {
	SOC_OMAP_CFG_ACL_LIST_1(SOC_OMAP_CFG_ACL_LIST_ACLE)
	{ .ppa = ~0U, }
};

/* **** */

static
int soc_omap_cfg_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int soc_omap_cfg_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	soc_omap_cfg_ref cfg = param;

	/* **** */

	csx_mmio_ref mmio = cfg->mmio;
	ERR_NULL(mmio);

	csx_mmio_register_access_list(mmio, 0, _soc_omap_cfg_acl_0, (void*)cfg);
	csx_mmio_register_access_list(mmio, 0, _soc_omap_cfg_acl_1, (void*)cfg);

	/* **** */

	return(err);
}

static
int soc_omap_cfg_action_reset(int err, void *const param, action_ref)
{
	ACTION_LOG(reset);

	/* **** */

	soc_omap_cfg_ref cfg = param;

	if(!cfg->reset) {
		csx_mmio_access_list_reset(cfg->mmio, _soc_omap_cfg_acl_0, sizeof(uint32_t), cfg->data);
		csx_mmio_access_list_reset(cfg->mmio, _soc_omap_cfg_acl_1, sizeof(uint32_t), &cfg->data[0x100]);
		cfg->reset = 1;
	}

	/* **** */

	return(err);
}

ACTION_LIST(soc_omap_cfg_action_list,
	.list = {
		[_ACTION_EXIT] = {{ soc_omap_cfg_action_exit }, { 0 }, 0 },
		[_ACTION_INIT] = {{ soc_omap_cfg_action_init }, { 0 }, 0 },
		[_ACTION_RESET] = {{ soc_omap_cfg_action_reset }, { 0 }, 0 },
	}
);

/* **** */

soc_omap_cfg_ptr soc_omap_cfg_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_cfg_href h2cfg)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2cfg);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_cfg_ref cfg = handle_calloc(h2cfg, 1, sizeof(soc_omap_cfg_t));
	ERR_NULL(cfg);

	cfg->csx = csx;
	cfg->mmio = mmio;

	/* **** */

	return(cfg);
}
