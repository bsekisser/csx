#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_mpu.h"

#define _MPU(_x)			(CSX_MMIO_MPU_BASE + (_x))

#define MMIO_LIST \
	MMIO(0xfffe, 0xce00, 0x0000, 0x3000, 32, MEM_RW, ARM_CKCTL) \
	MMIO(0xfffe, 0xce04, 0x0000, 0x0400, 32, MEM_RW, ARM_IDLECT1) \
	MMIO(0xfffe, 0xce08, 0x0000, 0x0100, 32, MEM_RW, ARM_IDLECT2) \
	MMIO(0xfffe, 0xce14, 0x0000, 0x0000, 32, MEM_RW, ARM_RSTCT2) \
	MMIO(0xfffe, 0xce18, 0x0000, 0x0038, 32, MEM_RW, ARM_SYSST)

#include "csx_mmio_trace.h"

#define ARM_CKCTL			_MPU(0x000)
#define ARM_IDLECT(_x)		_MPU(((_x) & 0x03) << 2)
#define ARM_RSTCT2			_MPU(0x014)
#define ARM_SYSST			_MPU(0x018)

static uint32_t csx_mmio_mpu_read(void* data, uint32_t addr, uint8_t size)
{
	const csx_mmio_mpu_p mpu = data;
	const csx_p csx = mpu->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint8_t offset = addr & _BM(8);

	uint32_t value = 0;
	
	switch(addr)
	{
		case ARM_CKCTL:
			value = mpu->arm_ckctl;
			break;
		case ARM_IDLECT(1):
		case ARM_IDLECT(2):
			value = mpu->arm_idlect[(offset - 1) & 1];
			break;
		case ARM_RSTCT2:
			value = mpu->arm_rstct2;
			break;
		case ARM_SYSST:
			value = mpu->arm_sysst;
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
//	return(csx_data_read((uint8_t*)&value, size));
	return(value);
}

static void csx_mmio_mpu_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const csx_mmio_mpu_p mpu = data;
	const csx_p csx = mpu->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);

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
			mpu->arm_ckctl = value;
			break;
		case ARM_IDLECT(1):
			if(1)
			{
				LOG("IDL_CLKOUT_ARM: %01u, WKUP_MODE: %01u, IDLTIM_ARM: %01u, IDLAPI_ARM: %01u",
					BEXT(value, 12), BEXT(value, 10),
					BEXT(value, 9), BEXT(value, 8));
				LOG("IDLDPLL_ARM: %01u, IDLIF_ARM: %01u, IDLPER_ARM: %01u, IDLXOPR_ARM: %01u, IDLWDT_ARM: %01u",
					BEXT(value, 7), BEXT(value, 6), BEXT(value, 2),
					BEXT(value, 1), BEXT(value, 0));
			}
			mpu->arm_idlect[(offset - 1) & 1] = value;
			break;
		case ARM_IDLECT(2):
			if(1)
			{
				LOG("EN_CKOUT_ARM: %01u, DMACK_REQ: %01u, EN_TIMCK: %01u, EN_APICK: %01u",
					BEXT(value, 11), BEXT(value, 8), BEXT(value, 7),
					BEXT(value, 6));
				LOG("EN_LCDCK: %01u, EN_PERCK: %01u, EN_XORPCK: %01u, EN_WDTCK: %01u",
					BEXT(value, 3), BEXT(value, 2), BEXT(value, 1), BEXT(value, 0));
			}
			mpu->arm_idlect[(offset - 1) & 1] = value;
			break;
		case ARM_RSTCT2:
			if(1)
				LOG("PER_EN: %01u", BEXT(value, 0));
			mpu->arm_rstct2 = value;
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
			mpu->arm_sysst = value & ~mlBF(5, 0);
			break;
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;
	}
}

static void csx_mmio_mpu_reset(void* data)
{
	const csx_mmio_mpu_p mpu = data;

	mpu->arm_ckctl		= 0x00003000;
	mpu->arm_idlect[0]	= 0x00000400;
	mpu->arm_idlect[1]	= 0x00000100;
	mpu->arm_rstct2		= 0x00000000;
	mpu->arm_sysst		= 0x00000038;
}

static csx_mmio_peripheral_t mpu_peripheral = {
	.base = CSX_MMIO_MPU_BASE,

	.reset = csx_mmio_mpu_reset,

	.read = csx_mmio_mpu_read,
	.write = csx_mmio_mpu_write,
};

int csx_mmio_mpu_init(csx_p csx, csx_mmio_p mmio, csx_mmio_mpu_h h2mpu)
{
	csx_mmio_mpu_p mpu;
	
	ERR_NULL(mpu = malloc(sizeof(csx_mmio_mpu_t)));
	if(!mpu)
		return(-1);

	mpu->csx = csx;
	mpu->mmio = mmio;
	
	*h2mpu = mpu;
	
	csx_mmio_peripheral(mmio, &mpu_peripheral, mpu);
	
	return(0);
}
