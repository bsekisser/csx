#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define MMIO_CFG_LIST \
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

#define MMIO_DPLL_LIST \
	MMIO(0xfffe, 0xcf00, 0x0000, 0x2002, 32, MEM_RW, DPLL1_CTL_REG)

#define MMIO_GP_TIMER_LIST \
	MMIO(0xfffb, 0x1c10, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TIOCP_CFG) \
	MMIO(0xfffb, 0x1c18, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TISR) \
	MMIO(0xfffb, 0x1c1c, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TIER) \
	MMIO(0xfffb, 0x1c20, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TWER) \
	MMIO(0xfffb, 0x1c24, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TCLR) \
	MMIO(0xfffb, 0x1c2c, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TLDR) \
	MMIO(0xfffb, 0x1c38, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TMAR) \
	MMIO(0xfffb, 0x1c40, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TSICR) \
	\
	MMIO(0xfffb, 0x2410, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TIOCP_CFG) \
	MMIO(0xfffb, 0x2418, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TISR) \
	MMIO(0xfffb, 0x241c, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TIER) \
	MMIO(0xfffb, 0x2420, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TWER) \
	MMIO(0xfffb, 0x2424, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TCLR) \
	MMIO(0xfffb, 0x242c, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TLDR) \
	MMIO(0xfffb, 0x2438, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TMAR) \
	MMIO(0xfffb, 0x2440, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TSICR) \
	\
	MMIO(0xfffb, 0x3410, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TIOCP_CFG) \
	MMIO(0xfffb, 0x3418, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TISR) \
	MMIO(0xfffb, 0x341c, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TIER) \
	MMIO(0xfffb, 0x3420, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TWER) \
	MMIO(0xfffb, 0x3424, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TCLR) \
	MMIO(0xfffb, 0x342c, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TLDR) \
	MMIO(0xfffb, 0x3438, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TMAR) \
	MMIO(0xfffb, 0x3440, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TSICR)

#define MMIO_MPU_LIST \
	MMIO(0xfffe, 0xce00, 0x0000, 0x3000, 32, MEM_RW, ARM_CKCTL) \
	MMIO(0xfffe, 0xce04, 0x0000, 0x0400, 32, MEM_RW, ARM_IDLECT1) \
	MMIO(0xfffe, 0xce08, 0x0000, 0x0100, 32, MEM_RW, ARM_IDLECT2) \
	MMIO(0xfffe, 0xce14, 0x0000, 0x0000, 32, MEM_RW, ARM_RSTCT2) \
	MMIO(0xfffe, 0xce18, 0x0000, 0x0038, 32, MEM_RW, ARM_SYSST)

#define MMIO_MPU_GPIO1_LIST \
	MMIO(0xfffb, 0xe430, 0x0000, 0x0000, 32, MEM_RW, GPIO1_DATAOUT) \
	MMIO(0xfffb, 0xe434, 0x0000, 0xffff, 32, MEM_RW, GPIO1_DIRECTION)

#define MMIO_MPU_GPIO2_LIST \
	MMIO(0xfffb, 0xec30, 0x0000, 0x0000, 32, MEM_RW, GPIO2_DATAOUT) \
	MMIO(0xfffb, 0xec34, 0x0000, 0xffff, 32, MEM_RW, GPIO2_DIRECTION)

#define MMIO_MPU_GPIO3_LIST \
	MMIO(0xfffb, 0xb430, 0x0000, 0x0000, 32, MEM_RW, GPIO3_DATAOUT) \
	MMIO(0xfffb, 0xb434, 0x0000, 0xffff, 32, MEM_RW, GPIO3_DIRECTION)

#define MMIO_MPU_GPIO4_LIST \
	MMIO(0xfffb, 0xbc30, 0x0000, 0x0000, 32, MEM_RW, GPIO4_DATAOUT) \
	MMIO(0xfffb, 0xbc34, 0x0000, 0xffff, 32, MEM_RW, GPIO4_DIRECTION)

#define MMIO_MPU_GPIOx_LIST \
	MMIO_MPU_GPIO1_LIST \
	MMIO_MPU_GPIO2_LIST \
	MMIO_MPU_GPIO3_LIST \
	MMIO_MPU_GPIO4_LIST

#define MMIO_MPU_L1_IHR_LIST \
	MMIO(0xfffe, 0xcb04, 0xffff, 0xffff, 32, MEM_RW, MPU_L1_MIR)

#define MMIO_OCP_LIST \
	MMIO(0xfffe, 0xcc14, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS1_CONFIG) \
	MMIO(0xfffe, 0xcc18, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS2_CONFIG) \
	MMIO(0xfffe, 0xcc1c, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS3_CONFIG) \
	MMIO(0xfffe, 0xcc50, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS0_CONFIG) \
	MMIO(0xfffe, 0xcc54, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS1_CONFIG) \
	MMIO(0xfffe, 0xcc58, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS2_CONFIG) \
	MMIO(0xfffe, 0xcc5c, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS3_CONFIG)

#define MMIO_OS_TIMER_LIST \
	MMIO(0xfffb, 0x9000, 0x00ff, 0xffff, 32, MEM_RW, OS_TIMER_TICK_VAL) \
	MMIO(0xfffb, 0x9008, 0x0000, 0x0008, 32, MEM_RW, OS_TIMER_CTRL)

#define MMIO_TIMER_LIST \
	MMIO(0xfffe, 0xc500, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_1) \
	MMIO(0xfffe, 0xc504, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_1) \
	MMIO(0xfffe, 0xc508, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_1) \
	MMIO(0xfffe, 0xc600, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_2) \
	MMIO(0xfffe, 0xc604, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_2) \
	MMIO(0xfffe, 0xc608, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_2) \
	MMIO(0xfffe, 0xc700, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_3) \
	MMIO(0xfffe, 0xc704, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIMER_3) \
	MMIO(0xfffe, 0xc708, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIMER_3)

/* **** */

#define MMIO_LIST \
	MMIO_CFG_LIST \
	MMIO_DPLL_LIST \
	MMIO_GP_TIMER_LIST \
	MMIO_MPU_LIST \
	MMIO_MPU_GPIOx_LIST \
	MMIO_MPU_L1_IHR_LIST \
	MMIO_OCP_LIST \
	MMIO_OS_TIMER_LIST \
	MMIO_TIMER_LIST

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

/* **** */

void soc_mmio_dpll_write(void* param, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_p mmio = param;
//	const csx_p csx = mmio->csx;
	
	soc_mmio_trace(mmio, trace_list, addr);

	switch(addr)
	{
		case	DPLL1_CTL_REG:
		{
			int pll_enable = BEXT(value, 4);
			if(1)
			{
				LOG("LS_DISABLE: %01u, IAI: %01u, IOB: %01u, TEST: %01u",
					BEXT(value, 15), BEXT(value, 14), BEXT(value, 13),
					BEXT(value, 12));
				LOG("PLL_MULT: %02u, PLL_DIV: %01u, PLL_ENABLE: %01u",
					mlBFEXT(value, 11, 7), mlBFEXT(value, 6, 5), pll_enable);
				LOG("BYPASS_DIV: %01u, BREAKLN: %01u, LOCK: %01u",
					 mlBFEXT(value, 3, 2), BEXT(value, 1), BEXT(value, 0));
			}
			value |= pll_enable;
		}	break;
		default:
//			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;	
	}
	
	soc_mmio_write(mmio, addr, value, size);
}

static void soc_mmio_mpu_write(void* param, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_p mmio = param;
//	const csx_p csx = mmio->csx;
	
	soc_mmio_trace(mmio, trace_list, addr);

	uint8_t offset = addr & _BM(8);
	
	switch(addr)
	{
		case ARM_CKCTL:
			if(1)
			{
				LOG("ARM_INTHCK_SEL: %01u, EN_DSPCK: %01u, ARM_TIMXO: %01u, DSPMMUDIV: %01u",
					BEXT(value, 14), BEXT(value, 13),
					BEXT(value, 12), mlBFEXT(value, 11, 10));
				LOG("TCDIV: %01u, DSPDIV: %01u, ARMDIV: %01u, LCDDIV: %01u, ARM_PERDIV: %01u",
					mlBFEXT(value, 9, 8), mlBFEXT(value, 7, 6),
					mlBFEXT(value, 5, 4), mlBFEXT(value, 3, 2),
					mlBFEXT(value, 1, 0));
			}
			break;
		case ARM_IDLECT1:
			if(1)
			{
				LOG("IDL_CLKOUT_ARM: %01u, WKUP_MODE: %01u, IDLTIM_ARM: %01u, IDLAPI_ARM: %01u",
					BEXT(value, 12), BEXT(value, 10),
					BEXT(value, 9), BEXT(value, 8));
				LOG("IDLDPLL_ARM: %01u, IDLIF_ARM: %01u, IDLPER_ARM: %01u, IDLXOPR_ARM: %01u, IDLWDT_ARM: %01u",
					BEXT(value, 7), BEXT(value, 6), BEXT(value, 2),
					BEXT(value, 1), BEXT(value, 0));
			}
			break;
		case ARM_IDLECT2:
			if(1)
			{
				LOG("EN_CKOUT_ARM: %01u, DMACK_REQ: %01u, EN_TIMCK: %01u, EN_APICK: %01u",
					BEXT(value, 11), BEXT(value, 8), BEXT(value, 7),
					BEXT(value, 6));
				LOG("EN_LCDCK: %01u, EN_PERCK: %01u, EN_XORPCK: %01u, EN_WDTCK: %01u",
					BEXT(value, 3), BEXT(value, 2), BEXT(value, 1), BEXT(value, 0));
			}
			break;
		case ARM_RSTCT2:
			if(1)
				LOG("PER_EN: %01u", BEXT(value, 0));
			break;
		case ARM_SYSST:
			if(1)
			{
				LOG("CLOCK_SELECT: %01u, IDLE_DSP: %01u, POR: %01u, EXT_RST: %01u",
					mlBFEXT(value, 13, 11), BEXT(value, 6),
					BEXT(value, 5), BEXT(value, 4));
				LOG("ARM_MCRST: %01u, ARM_WDRST: %01u, GLOB_SWRST: %01u, DSP_WDRST: %01u",
					BEXT(value, 3), BEXT(value, 2),
					BEXT(value, 1), BEXT(value, 0));
			}
			value &= ~mlBF(5, 0);
			break;
		default:
//			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}

	soc_mmio_write(mmio, addr, value, size);
}

#define _OCP(_x)				(CSX_MMIO_OCP_BASE + (_x))

#define EMIFS_CS_CONFIG(_x)			_OCP(0x10 + (((_x) & 3) << 2))
#define EMIFS_ADV_CS_CONFIG(_x)		_OCP(0x50 + (((_x) & 3) << 2))

static void soc_mmio_ocp_write(void* param, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_p mmio = param;
//	const csx_p csx = mmio->csx;
	
	soc_mmio_trace(mmio, trace_list, addr);

	switch(addr & ~0xf)
	{
		case EMIFS_ADV_CS_CONFIG(0):
		{
			LOG("BTMODE: %01u, ADVHOLD: %01u, OEHOLD: %01u, OESETUP: %01u",
				BEXT(value, 9), BEXT(value, 8), mlBFEXT(value, 7, 4), mlBFEXT(value, 3, 0));
		}	break;
		case EMIFS_CS_CONFIG(0):
		{
			LOG("PGWSTEN: %01u, PGWST: %01u, BTWST: %01u, MAD: %01u, BW: %01u",
				BEXT(value, 31), mlBFEXT(value, 30, 27),
				mlBFEXT(value, 26, 23), BEXT(value, 22), BEXT(value, 20));
			
			int rdmode = mlBFEXT(value, 18, 16);
			LOG("RDMODE: %01u, PGWST/WELEN: %01u, WRWST: %01u, RDWST: %01u",
				rdmode, mlBFEXT(value, 15, 12), mlBFEXT(value, 11, 8), mlBFEXT(value, 7, 4));
			
			const char *rdmodesl[] = {
				"0x000, Mode 0: Asyncronous read",
				"0x001, Mode 1: Page mode ROM read - 4 words per page",
				"0x010, Mode 2: Page mode ROM read - 8 words per page",
				"0x011, Mode 3: Page mode ROM read - 16 words per page",
				"0x100, Mode 4: Syncronous burst read mode",
				"0x101, Mode 5: Syncronous burst read mode",
				"0x110, Reserved for future expansion",
				"0x111, Mode 7: Syncronous burst read mode"};
			
			LOG("%s", rdmodesl[rdmode & 0x07]);
			
			LOG("RT: %01u, FCLKDIV: %01u", BEXT(value, 2), mlBFEXT(value, 1, 0));
		}	break;		
		default:
			LOG("addr = 0x%08x, cs = 0x%02x", addr, addr & 0xc);
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;	
	}

	soc_mmio_write(mmio, addr, value, size);
}

static uint32_t soc_mmio_os_timer_read(void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_os_timer_p ost = data;
	const csx_p csx = ost->csx;
	
	soc_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value = soc_mmio_read(mmio, addr, size);
	
	switch(addr)
	{
		case	OS_TIMER_CTRL:
			BCLR(value, 1);
			break;
		default:
//			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
	return(value);
}

static void soc_mmio_os_timer_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_os_timer_p ost = data;
	const csx_p csx = ost->csx;
	
	soc_mmio_trace(csx->mmio, trace_list, addr);

	switch(addr)
	{
		case	OS_TIMER_CTRL:
//			ost->ctrl = value;
			break;
		case	OS_TIMER_TICK_VAL:
//			ost->tick_val = value;
//			ost->base = csx->cycle;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

/* **** */

#define _TIMER(_t, _x)		(CSX_MMIO_TIMER(_t) | (_x))

#define MPU_CNTL_TIMER(_t)	_TIMER((_t), 0x00)
#define MPU_LOAD_TIMER(_t)	_TIMER((_t), 0x04)
#define MPU_READ_TIMER(_t)	_TIMER((_t), 0x08)

static uint32_t soc_mmio_timer_read(void* data, uint32_t addr, uint8_t size)
{
	const soc_mmio_timer_p t = data;
	const csx_p csx = t->csx;

	soc_mmio_trace(csx->mmio, trace_list, addr);

	uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;
	uint32_t value = 0;
	
	switch(addr)
	{
		case MPU_READ_TIMER(0):
		case MPU_READ_TIMER(1):
		case MPU_READ_TIMER(2):
			value = csx->cycle - t->unit[timer].base;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
//	return(soc_data_read((uint8_t*)&value, size));
	return(value);
}

static void soc_mmio_timer_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_timer_p t = data;
	const csx_p csx = t->csx;
	
	soc_mmio_trace(csx->mmio, trace_list, addr);

	uint8_t timer = ((addr - CSX_MMIO_TIMER_BASE) >> 8) & 3;
	
	switch(addr)
	{
		case MPU_CNTL_TIMER(0):
		case MPU_CNTL_TIMER(1):
		case MPU_CNTL_TIMER(2):
			t->unit[timer].cntl = value;
			break;
		case MPU_LOAD_TIMER(0):
		case MPU_LOAD_TIMER(1):
		case MPU_LOAD_TIMER(2):
			t->unit[timer].base = csx->cycle;
			t->unit[timer].value = value;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

/* **** */

static soc_mmio_peripheral_t cfg_peripheral[2] = {
	[0] = {
		.base = CSX_MMIO_CFG_BASE,

//		.reset = soc_mmio_cfg_reset,
		
//		.read = soc_mmio_cfg_read,
//		.write = soc_mmio_cfg_write,
	},

	[1] = {
		.base = CSX_MMIO_CFG_BASE + 0x100,

//		.reset = soc_mmio_cfg_reset,
		
//		.read = soc_mmio_cfg_read,
//		.write = soc_mmio_cfg_write,
	}
};

static soc_mmio_peripheral_t dpll_peripheral = {
	.base = CSX_MMIO_DPLL_BASE,

//	.reset = soc_mmio_dpll_reset,

//	.read = soc_mmio_dpll_read,
	.write = soc_mmio_dpll_write,
};

#define CSX_MMIO_GP_TIMER(_t)	(CSX_MMIO_GP_TIMER_BASE + (((_t) & 7) << 11))

static soc_mmio_peripheral_t gp_timer_peripheral[7] = {
	[0] = {
		.base = CSX_MMIO_GP_TIMER(0),

//		.reset = soc_mmio_gp_timer_reset,

//		.read = soc_mmio_gp_timer_read,
//		.write = soc_mmio_gp_timer_write
	},
	[1] = {
		.base = CSX_MMIO_GP_TIMER(1),

//		.reset = soc_mmio_gp_timer_reset,

//		.read = soc_mmio_gp_timer_read,
//		.write = soc_mmio_gp_timer_write
	},
	[2] = {
		.base = CSX_MMIO_GP_TIMER(2),

//		.reset = soc_mmio_gp_timer_reset,

//		.read = soc_mmio_gp_timer_read,
//		.write = soc_mmio_gp_timer_write
	},
	[3] = {
		.base = CSX_MMIO_GP_TIMER(3),

//		.reset = soc_mmio_gp_timer_reset,

//		.read = soc_mmio_gp_timer_read,
//		.write = soc_mmio_gp_timer_write
	},
	[4] = {
		.base = CSX_MMIO_GP_TIMER(4),

//		.reset = soc_mmio_gp_timer_reset,

//		.read = soc_mmio_gp_timer_read,
//		.write = soc_mmio_gp_timer_write
	},
	[5] = {
		.base = CSX_MMIO_GP_TIMER(5),

//		.reset = soc_mmio_gp_timer_reset,

//		.read = soc_mmio_gp_timer_read,
//		.write = soc_mmio_gp_timer_write
	},
	[6] = {
		.base = CSX_MMIO_GP_TIMER(6),

//		.reset = soc_mmio_gp_timer_reset,

//		.read = soc_mmio_gp_timer_read,
//		.write = soc_mmio_gp_timer_write
	}
};

static soc_mmio_peripheral_t mpu_peripheral = {
	.base = CSX_MMIO_MPU_BASE,

//	.reset = soc_mmio_mpu_reset,

//	.read = soc_mmio_mpu_read,
	.write = soc_mmio_mpu_write,
};

static soc_mmio_peripheral_t mpu_gpio_peripheral[] = {
	[0] = {
		.base = CSX_MMIO_MPU_GPIO1_BASE,

//		.reset = soc_mmio_mpu_gpio_reset,

//		.read = soc_mmio_mpu_gpio_read,
//		.write = soc_mmio_mpu_gpio_write,
	},
	[1] = {
		.base = CSX_MMIO_MPU_GPIO2_BASE,

//		.reset = soc_mmio_mpu_gpio_reset,

//		.read = soc_mmio_mpu_gpio_read,
//		.write = soc_mmio_mpu_gpio_write,
	},
	[2] = {
		.base = CSX_MMIO_MPU_GPIO3_BASE,

//		.reset = soc_mmio_mpu_gpio_reset,

//		.read = soc_mmio_mpu_gpio_read,
//		.write = soc_mmio_mpu_gpio_write,
	},
	[3] = {
		.base = CSX_MMIO_MPU_GPIO4_BASE,

//		.reset = soc_mmio_mpu_gpio_reset,

//		.read = soc_mmio_mpu_gpio_read,
//		.write = soc_mmio_mpu_gpio_write,
	},
};

static soc_mmio_peripheral_t mpu_l1_ihr_peripheral = {
	.base = CSX_MMIO_MPU_L1_IHR_BASE,

//	.reset = soc_mmio_mpu_l1_ihr_reset,

//	.read = soc_mmio_mpu_l1_ihr_read,
//	.write = soc_mmio_mpu_l1_ihr_write
};

static soc_mmio_peripheral_t ocp_peripheral = {
	.base = CSX_MMIO_OCP_BASE,

//	.reset = soc_mmio_ocp_reset,

//	.read = soc_mmio_ocp_read,
	.write = soc_mmio_ocp_write,
};

static soc_mmio_peripheral_t os_timer_peripheral = {
	.base = CSX_MMIO_OS_TIMER_BASE,

//	.reset = soc_mmio_os_timer_reset,

	.read = soc_mmio_os_timer_read,
	.write = soc_mmio_os_timer_write
};

static soc_mmio_peripheral_t timer_peripheral[3] = {
	[0] = {
		.base = CSX_MMIO_TIMER(0),

		.reset = soc_mmio_timer_reset,

		.read = soc_mmio_timer_read,
		.write = soc_mmio_timer_write
	},
	[1] = {
		.base = CSX_MMIO_TIMER(1),

//		.reset = soc_mmio_timer_reset,

		.read = soc_mmio_timer_read,
		.write = soc_mmio_timer_write
	},
	[2] = {
		.base = CSX_MMIO_TIMER(2),

//		.reset = soc_mmio_timer_reset,

		.read = soc_mmio_timer_read,
		.write = soc_mmio_timer_write
	},
};

/* **** */

int soc_mmio_omap_init(soc_mmio_p mmio/*, soc_mmio_omap_h h2omap*/)
{
	soc_mmio_peripheral(mmio, &cfg_peripheral[0], 0);
	soc_mmio_peripheral(mmio, &cfg_peripheral[1], 0);
	soc_mmio_peripheral(mmio, &dpll_peripheral, 0);
	for(int i = 0; i < 7; i++)
		soc_mmio_peripheral(mmio, &gp_timer_peripheral[i], 0);
	soc_mmio_peripheral(mmio, &mpu_peripheral, 0);
	for(int i = 0; i < 4; i++)
		soc_mmio_peripheral(mmio, &mpu_gpio_peripheral[i], 0);
	soc_mmio_peripheral(mmio, &l1_ihr_peripheral, 0);
	soc_mmio_peripheral(mmio, &ocp_peripheral, 0);
	soc_mmio_peripheral(mmio, &os_timer_peripheral, 0);
	for(int i = 0; i < 3; i++)
		soc_mmio_peripheral(mmio, &timer_peripheral[i], 0);

	return(0);
}
