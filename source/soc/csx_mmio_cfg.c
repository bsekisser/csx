#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_cfg.h"

#define _CFG(_x)		(CSX_MMIO_CFG_BASE + (_x & _BM(12)))

#define MMIO_LIST \
	MMIO(0xfffe, 0x100c, 0x0000, 0x0000, 32, MEM_RW, COMP_MODE_CTRL_0) \
	MMIO(0xfffe, 0x1038, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_D) \
	MMIO(0xfffe, 0x1060, 0x0000, 0x0000, 32, MEM_RW, VOLTAGE_CTRL_0) \
	MMIO(0xfffe, 0x1110, 0x0000, 0x0000, 32, MEM_RW, MOD_CONF_CTRL_1) \
	MMIO(0xfffe, 0x1140, 0x0000, 0x007f, 32, MEM_RW, RESET_CTL) \
	MMIO(0xfffe, 0x1160, 0x0000, 0x0000, 32, MEM_TRACE_RW, x0xfffe_0x1160)

#include "csx_mmio_trace.h"

#define COMP_MODE_CTRL_0	_CFG(0x000c)
#define FUNC_MUX_CTRL_D		_CFG(0x0038)
#define VOLTAGE_CTRL_0		_CFG(0x0060)
#define MOD_CONF_CTRL_0		_CFG(0x0110)
#define RESET_CTL			_CFG(0x0140)
#define esac_oxfffe1160		_CFG(0x0160)

uint32_t csx_mmio_cfg_read(csx_mmio_cfg_p cfg, uint32_t addr, uint8_t size)
{
	csx_p csx = cfg->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value;
	
	switch(addr)
	{
		case	esac_oxfffe1160:
			value = cfg->oxfffe1160;
			break;
	/* **** */ 
		case	COMP_MODE_CTRL_0:
			value = cfg->comp.mode_ctrl;
			break;
		case	FUNC_MUX_CTRL_D:
			value = cfg->mux['D' - 'A'].ctrl;
			break;
		case	MOD_CONF_CTRL_0:
			value = cfg->mod_conf_ctrl_0;
			break;
		case	RESET_CTL:
			value = cfg->reset_ctl;
			break;
		case	VOLTAGE_CTRL_0:
			value = cfg->voltage_ctrl_0;
			break;
	/* **** */ 
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
//	return(csx_data_read((uint8_t*)&value, size));
	return(value);
}

void csx_mmio_cfg_write(csx_mmio_cfg_p cfg, uint32_t addr, uint32_t value, uint8_t size)
{
	csx_p csx = cfg->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);
	
	switch(addr)
	{
		case	esac_oxfffe1160:
			cfg->oxfffe1160 = value;
			break;
	/* **** */
		case	COMP_MODE_CTRL_0:
			cfg->comp.mode_ctrl = value;
			break;
		case	FUNC_MUX_CTRL_D:
			cfg->mux['D' - 'A'].ctrl = value;
			break;
		case	MOD_CONF_CTRL_0:
			cfg->mod_conf_ctrl_0 = value;
			break;
		case	VOLTAGE_CTRL_0:
			cfg->voltage_ctrl_0 = value;
			break;
		case	RESET_CTL:
			cfg->reset_ctl = value;
			break;
	/* **** */
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

void csx_mmio_cfg_reset(csx_mmio_cfg_p cfg)
{
	cfg->oxfffe1160 = 0x00000000;
	cfg->comp.mode_ctrl = 0x00000000;
	
	for(int i = 'A'; i <= 'D'; i++)
		cfg->mux[i - 'A'].ctrl = 0x00000000;

	cfg->mod_conf_ctrl_0 = 0x00000000;
	cfg->reset_ctl = 0x0000007f;
	cfg->voltage_ctrl_0 = 0x00000000;
}

int csx_mmio_cfg_init(csx_p csx, csx_mmio_p mmio, csx_mmio_cfg_h h2cfg)
{
	csx_mmio_cfg_p cfg;
	
	ERR_NULL(cfg = malloc(sizeof(csx_mmio_cfg_t)));
	if(!cfg)
		return(-1);

	cfg->csx = csx;
	cfg->mmio = mmio;
	
	*h2cfg = cfg;
	
	return(0);
}
