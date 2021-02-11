#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_cfg.h"

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

#include "csx_mmio_trace.h"

#define COMP_MODE_CTRL_0	_CFG(0x000c)
#define FUNC_MUX_CTRL_3		_CFG(0x0010)
#define FUNC_MUX_CTRL_D		_CFG(0x0038)
#define FUNC_MUX_CTRL_E		_CFG(0x0090)
#define FUNC_MUX_CTRL_12	_CFG(0x00a0)
#define VOLTAGE_CTRL_0		_CFG(0x0060)
#define MOD_CONF_CTRL_0		_CFG(0x0110)
#define RESET_CTL			_CFG(0x0140)
#define esac_oxfffe1160		_CFG(0x0160)

static uint32_t cfg_data_rw(csx_mmio_cfg_p cfg, uint32_t addr, uint32_t* value, uint32_t size)
{
	const uint32_t offset = addr - CSX_MMIO_CFG_BASE;
	uint8_t* ptr = &cfg->data[offset & 0x1ff];
	
	if(value)
		csx_data_write(ptr, *value, size);
	else
		return(csx_data_read(ptr, size));
	
	return(0);
}

static uint32_t csx_mmio_cfg_read(void* data, uint32_t addr, uint8_t size)
{
	csx_mmio_cfg_p cfg = data;
	csx_p csx = cfg->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value = cfg_data_rw(cfg, addr, 0, size);
	
	switch(addr)
	{
		case	esac_oxfffe1160:
			break;
	/* **** */ 
		case	COMP_MODE_CTRL_0:
		case	FUNC_MUX_CTRL_3...FUNC_MUX_CTRL_D:
		case	FUNC_MUX_CTRL_E...FUNC_MUX_CTRL_12:
		case	MOD_CONF_CTRL_0:
		case	PU_PD_SEL_0...PU_PD_SEL_4:
		case	PULL_DWN_CTRL_0...PULL_DWN_CTRL_3:
		case	PULL_DWN_CTRL_4:
		case	RESET_CTL:
		case	USB_TRANSCEIVER_CTRL:
		case	VOLTAGE_CTRL_0:
			break;
	/* **** */ 
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
//	return(csx_data_read((uint8_t*)&value, size));
	return(value);
}

static void csx_mmio_cfg_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	csx_mmio_cfg_p cfg = data;
	csx_p csx = cfg->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);
	
	switch(addr)
	{
		case	esac_oxfffe1160:
			break;
	/* **** */
		case	COMP_MODE_CTRL_0:
		case	FUNC_MUX_CTRL_3...FUNC_MUX_CTRL_D:
		case	FUNC_MUX_CTRL_E...FUNC_MUX_CTRL_12:
		case	MOD_CONF_CTRL_0:
		case	PU_PD_SEL_0...PU_PD_SEL_4:
		case	PULL_DWN_CTRL_0...PULL_DWN_CTRL_3:
		case	PULL_DWN_CTRL_4:
		case	RESET_CTL:
		case	USB_TRANSCEIVER_CTRL:
		case	VOLTAGE_CTRL_0:
			break;
	/* **** */
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}

	cfg_data_rw(cfg, addr, &value, size);
}

static void csx_mmio_cfg_reset(void* data)
{
	csx_mmio_cfg_p cfg = data;

	for(int i = 0; i < 0x1ff; i++)
		cfg->data[i] = 0;

	int i = 0;
	do {
		ea_trace_p tle = &trace_list[i++];

		if(0) LOG("tle = 0x%08x, name = %s", (uint32_t)tle, tle->name);

		uint32_t value = tle->reset_value;
		if(value)
			cfg_data_rw(cfg, tle->address, &value, tle->size);
	}while(trace_list[i].address);
}

static csx_mmio_peripheral_t cfg_peripheral[2] = {
	[0] = {
		.base = CSX_MMIO_CFG_BASE,

		.reset = csx_mmio_cfg_reset,
		
		.read = csx_mmio_cfg_read,
		.write = csx_mmio_cfg_write,
	},

	[1] = {
		.base = CSX_MMIO_CFG_BASE + 0x100,

	//	.reset = csx_mmio_cfg_reset,
		
		.read = csx_mmio_cfg_read,
		.write = csx_mmio_cfg_write,
	}
};

int csx_mmio_cfg_init(csx_p csx, csx_mmio_p mmio, csx_mmio_cfg_h h2cfg)
{
	csx_mmio_cfg_p cfg;
	
	ERR_NULL(cfg = malloc(sizeof(csx_mmio_cfg_t)));
	if(!cfg)
		return(-1);

	cfg->csx = csx;
	cfg->mmio = mmio;
	
	*h2cfg = cfg;
	
	csx_mmio_peripheral(mmio, &cfg_peripheral[0], (void*)cfg);
	csx_mmio_peripheral(mmio, &cfg_peripheral[1], (void*)cfg);
	
	return(0);
}
