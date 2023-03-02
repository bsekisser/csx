#include "soc_mmio_cfg.h"

#include "soc_mmio_omap.h"

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

#define _CFG(_x)		(CSX_MMIO_CFG_BASE + (_x & _BM(12)))

#define MMIO_LIST_0 \
	MMIO_TRACE_LIST_HEAD(0) \
	MMIO(0xfffe, 0x100c, 0x0000, 0x0000, 32, MEM_RW, COMP_MODE_CTRL_0) \
	MMIO(0xfffe, 0x1010, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_3) \
	MMIO(0xfffe, 0x1014, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_4) \
	MMIO(0xfffe, 0x1018, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_5) \
	MMIO(0xfffe, 0x101c, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_6) \
	MMIO(0xfffe, 0x1020, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_7) \
	MMIO(0xfffe, 0x1024, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_8) \
	MMIO(0xfffe, 0x1028, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_9) \
	MMIO(0xfffe, 0x102c, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_A) \
	MMIO(0xfffe, 0x1030, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_B) \
	MMIO(0xfffe, 0x1034, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_C) \
	MMIO(0xfffe, 0x1038, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_D) \
	MMIO(0xfffe, 0x1040, 0x0000, 0x0000, 32, MEM_RW, PULL_DWN_CTRL_0) \
	MMIO(0xfffe, 0x1044, 0x0000, 0x0000, 32, MEM_RW, PULL_DWN_CTRL_1) \
	MMIO(0xfffe, 0x1048, 0x0000, 0x0000, 32, MEM_RW, PULL_DWN_CTRL_2) \
	MMIO(0xfffe, 0x104c, 0x0000, 0x0000, 32, MEM_RW, PULL_DWN_CTRL_3) \
	MMIO(0xfffe, 0x1060, 0x0000, 0x0000, 32, MEM_RW, VOLTAGE_CTRL_0) \
	MMIO(0xfffe, 0x1064, 0x0000, 0x0006, 32, MEM_RW, USB_TRANSCEIVER_CTRL) \
	MMIO(0xfffe, 0x1080, 0x0000, 0x0000, 32, MEM_RW, MOD_CONF_CTRL_0) \
	MMIO(0xfffe, 0x1090, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_E) \
	MMIO(0xfffe, 0x1094, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_F) \
	MMIO(0xfffe, 0x1098, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_10) \
	MMIO(0xfffe, 0x109c, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_11) \
	MMIO(0xfffe, 0x10a0, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_12) \
	MMIO(0xfffe, 0x10ac, 0x0000, 0x0000, 32, MEM_RW, PULL_DWN_CTRL_4) \
	MMIO(0xfffe, 0x10b4, 0x0000, 0x0000, 32, MEM_RW, PU_PD_SEL_0) \
	MMIO(0xfffe, 0x10b8, 0x0000, 0x0000, 32, MEM_RW, PU_PD_SEL_1) \
	MMIO(0xfffe, 0x10bc, 0x0000, 0x0000, 32, MEM_RW, PU_PD_SEL_2) \
	MMIO(0xfffe, 0x10c0, 0x0000, 0x0000, 32, MEM_RW, PU_PD_SEL_3) \
	MMIO(0xfffe, 0x10c4, 0x0000, 0x0000, 32, MEM_RW, PU_PD_SEL_4) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST_1 \
	MMIO_TRACE_LIST_HEAD(1) \
	MMIO(0xfffe, 0x1110, 0x0000, 0x0000, 32, MEM_RW, MOD_CONF_CTRL_1) \
	MMIO(0xfffe, 0x1140, 0x0000, 0x007f, 32, MEM_RW, RESET_CTL) \
	MMIO(0xfffe, 0x1160, 0x0000, 0x0000, 32, MEM_TRACE_RW, x0xfffe_0x1160) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST \
	MMIO_LIST_0 \
	MMIO_LIST_1

#include "soc_mmio_trace.h"

#include "soc_mmio_ea_trace_enum.h"
MMIO_ENUM_LIST

#include "soc_mmio_ea_trace_list.h"
MMIO_TRACE_LIST

#define COMP_MODE_CTRL_0	_CFG(0x000c)
#define FUNC_MUX_CTRL_3		_CFG(0x0010)
#define FUNC_MUX_CTRL_D		_CFG(0x0038)
#define FUNC_MUX_CTRL_E		_CFG(0x0090)
#define FUNC_MUX_CTRL_12	_CFG(0x00a0)
#define VOLTAGE_CTRL_0		_CFG(0x0060)
#define MOD_CONF_CTRL_1		_CFG(0x0110)
#define RESET_CTL			_CFG(0x0140)
#define esac_oxfffe1160		_CFG(0x0160)

static soc_mmio_peripheral_t cfg_peripheral[2] = {
	{
		.base = CSX_MMIO_CFG_BASE,
		.trace_list = trace_list_0,

		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_CFG_BASE + 0x100,
		.trace_list = trace_list_1,

		.reset = 0,

		.read = 0,
		.write = 0,
	}
};

int _mmio_cfg_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_mmio_cfg_h h2cfg = param;
//	soc_mmio_cfg_p cfg = *h2cfg;

	handle_free(param);

	return(0);
}

int _mmio_cfg_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

//	soc_mmio_cfg_p cfg = param;

	return(0);
	UNUSED(param);
}

int soc_mmio_cfg_init(csx_p csx, soc_mmio_p mmio, soc_mmio_cfg_h h2cfg)
{
	if(_trace_init) {
		LOG();
	}

	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2cfg);

	soc_mmio_cfg_p cfg = HANDLE_CALLOC(h2cfg, 1, sizeof(soc_mmio_cfg_t));
	ERR_NULL(cfg);

	cfg->csx = csx;
	cfg->mmio = mmio;

	soc_mmio_callback_atexit(mmio, _mmio_cfg_atexit, h2cfg);
	soc_mmio_callback_atreset(mmio, _mmio_cfg_atreset, cfg);

	soc_mmio_peripheral(mmio, &cfg_peripheral[0], (void*)cfg);
	soc_mmio_peripheral(mmio, &cfg_peripheral[1], (void*)cfg);

	return(0);
}
