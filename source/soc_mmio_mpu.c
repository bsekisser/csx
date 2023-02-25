#include "soc_mmio_mpu.h"

#include "csx_data.h"
#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define _MPU(_x)			(CSX_MMIO_MPU_BASE + (_x))

#define MMIO_LIST \
	MMIO(0xfffe, 0xce00, 0x0000, 0x3000, 32, MEM_RW, ARM_CKCTL) \
	MMIO(0xfffe, 0xce04, 0x0000, 0x0400, 32, MEM_RW, ARM_IDLECT1) \
	MMIO(0xfffe, 0xce08, 0x0000, 0x0100, 32, MEM_RW, ARM_IDLECT2) \
	MMIO(0xfffe, 0xce14, 0x0000, 0x0000, 32, MEM_RW, ARM_RSTCT2) \
	MMIO(0xfffe, 0xce18, 0x0000, 0x0038, 32, MEM_RW, ARM_SYSST)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

#define ARM_CKCTL			_MPU(0x000)
#define ARM_IDLECT(_x)		_MPU(((_x) & 0x03) << 2)
#define ARM_RSTCT2			_MPU(0x014)
#define ARM_SYSST			_MPU(0x018)

static void soc_mmio_mpu_write(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_mpu_p mpu = param;
	const csx_p csx = mpu->csx;

	const ea_trace_p eat = soc_mmio_trace(csx->mmio, trace_list, addr);
	if(eat)
	{
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
		}

		csx_data_write(data + (addr & 0xff), value, size);
	} else {
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

static soc_mmio_peripheral_t mpu_peripheral = {
	.base = CSX_MMIO_MPU_BASE,
	.trace_list = trace_list,

	.reset = 0,

	.read = 0,
	.write = soc_mmio_mpu_write,
};

static int _mpu_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	soc_mmio_mpu_h h2mpu = param;
	soc_mmio_mpu_p mpu = *h2mpu;
	
	free(mpu);
	*h2mpu = 0;
	
	return(0);
}

int soc_mmio_mpu_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_h h2mpu)
{
	// TODO: csx_mmio
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2mpu);

	if(_trace_init) {
		LOG();
	}

	soc_mmio_mpu_p mpu = calloc(1, sizeof(soc_mmio_mpu_t));

	ERR_NULL(mpu);
	if(!mpu)
		return(-1);

	mpu->csx = csx;
	mpu->mmio = mmio;

	*h2mpu = mpu;

	soc_mmio_callback_atexit(mmio, _mpu_atexit, h2mpu);
//	soc_mmio_callback_atreset(mmio, _mpu_atreset, mpu);

	soc_mmio_peripheral(mmio, &mpu_peripheral, mpu);

	return(0);
}
