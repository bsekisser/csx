#include "soc_omap_cfg.h"

/* **** */

#include "csx_data.h"
#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "bitfield.h"
#include "callback_list.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_cfg_t {
	csx_p csx;
	csx_mmio_p mmio;

	uint8_t data[0x0200];
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

#if 0
enum {
	SOC_OMAP_CFG_ACL_LIST_0(MMIO_ENUM)
	SOC_OMAP_CFG_ACL_LIST_1(MMIO_ENUM)
};
#endif

/* **** */

static int __soc_omap_cfg_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	handle_free(param);

	return(0);
}

static csx_mmio_access_list_t _soc_omap_cfg_acl_0[];
static csx_mmio_access_list_t _soc_omap_cfg_acl_1[];

static int __soc_omap_cfg_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	const soc_omap_cfg_p cfg = param;

	csx_mmio_access_list_reset(cfg->mmio, _soc_omap_cfg_acl_0, sizeof(uint32_t), cfg->data);
	csx_mmio_access_list_reset(cfg->mmio, _soc_omap_cfg_acl_1, sizeof(uint32_t), &cfg->data[0x100]);

	return(0);
	UNUSED(param);
}

/* **** */

static uint32_t _soc_omap_cfg_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_cfg_p cfg = param;

	const uint16_t offset = ppa & 0x1ff;

	const uint32_t data = csx_data_offset_mem_access(cfg->data, offset, size, write);

	CSX_MMIO_TRACE_MEM_ACCESS(cfg->csx, ppa, size, write, data);

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

int soc_omap_cfg_init(csx_p csx, csx_mmio_p mmio, soc_omap_cfg_h h2cfg)
{
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2cfg);

	if(_trace_init) {
		LOG();
	}

	soc_omap_cfg_p cfg = handle_calloc((void**)h2cfg, 1, sizeof(soc_omap_cfg_t));
	ERR_NULL(cfg);

	cfg->csx = csx;
	cfg->mmio = mmio;

	csx_mmio_callback_atexit(mmio, __soc_omap_cfg_atexit, h2cfg);
	csx_mmio_callback_atreset(mmio, __soc_omap_cfg_atreset, cfg);

	/* **** */

	csx_mmio_register_access_list(mmio, 0, _soc_omap_cfg_acl_0, (void*)cfg);
	csx_mmio_register_access_list(mmio, 0, _soc_omap_cfg_acl_1, (void*)cfg);

	/* **** */

	return(0);
}
