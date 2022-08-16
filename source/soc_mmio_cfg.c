#include "soc_mmio_cfg.h"

#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define _CFG(_x)		(CSX_MMIO_CFG_BASE + (_x & _BM(12)))

#define MMIO_LIST \
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
	MMIO(0xfffe, 0x1110, 0x0000, 0x0000, 32, MEM_RW, MOD_CONF_CTRL_1) \
	MMIO(0xfffe, 0x1140, 0x0000, 0x007f, 32, MEM_RW, RESET_CTL) \
	MMIO(0xfffe, 0x1160, 0x0000, 0x0000, 32, MEM_TRACE_RW, x0xfffe_0x1160)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

#define COMP_MODE_CTRL_0	_CFG(0x000c)
#define FUNC_MUX_CTRL_3		_CFG(0x0010)
#define FUNC_MUX_CTRL_D		_CFG(0x0038)
#define FUNC_MUX_CTRL_E		_CFG(0x0090)
#define FUNC_MUX_CTRL_12	_CFG(0x00a0)
#define VOLTAGE_CTRL_0		_CFG(0x0060)
#define MOD_CONF_CTRL_0		_CFG(0x0110)
#define RESET_CTL			_CFG(0x0140)
#define esac_oxfffe1160		_CFG(0x0160)

static soc_mmio_peripheral_t cfg_peripheral[2] = {
	[0] = {
		.base = CSX_MMIO_CFG_BASE,
		.trace_list = trace_list,

//		.reset = soc_mmio_cfg_reset,
		
//		.read = soc_mmio_cfg_read,
//		.write = soc_mmio_cfg_write,
	},

	[1] = {
		.base = CSX_MMIO_CFG_BASE + 0x100,
		.trace_list = trace_list,

//		.reset = soc_mmio_cfg_reset,
		
//		.read = soc_mmio_cfg_read,
//		.write = soc_mmio_cfg_write,
	}
};

int soc_mmio_cfg_init(csx_p csx, soc_mmio_p mmio, soc_mmio_cfg_h h2cfg)
{
	soc_mmio_cfg_p cfg;
	
	ERR_NULL(cfg = malloc(sizeof(soc_mmio_cfg_t)));
	if(!cfg)
		return(-1);

	cfg->csx = csx;
	cfg->mmio = mmio;
	
	*h2cfg = cfg;
	
	soc_mmio_peripheral(mmio, &cfg_peripheral[0], (void*)cfg);
	soc_mmio_peripheral(mmio, &cfg_peripheral[1], (void*)cfg);
	
	return(0);
}
