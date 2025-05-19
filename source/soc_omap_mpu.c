#include "soc_omap_mpu.h"

/* **** */

#include "csx_data.h"
#include "csx_soc_omap.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/callback_qlist.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_tag {
	csx_ptr csx;
	csx_mmio_ptr mmio;

	uint32_t ckctl;
	uint32_t idlct[2];
	uint32_t rstct[2];
	uint32_t sysst;

	callback_qlist_elem_t atexit;
}soc_omap_mpu_t;

/* **** */

#define SOC_MMIO_MPU_LIST(_MMIO) \
	_MMIO(0xfffe, 0xce00, 0x0000, 0x3000, ARM_CKCTL, soc_omap_mpu_ckctl) \
	_MMIO(0xfffe, 0xce04, 0x0000, 0x0400, ARM_IDLECT1, soc_omap_mpu_idlct1) \
	_MMIO(0xfffe, 0xce08, 0x0000, 0x0100, ARM_IDLECT2, soc_omap_mpu_idlct2) \
	_MMIO(0xfffe, 0xce14, 0x0000, 0x0000, ARM_RSTCT2, soc_omap_mpu_rstct2) \
	_MMIO(0xfffe, 0xce18, 0x0000, 0x0038, ARM_SYSST, soc_omap_mpu_sysst)

/* **** */

static int __soc_omap_mpu_atexit(void *const param)
{
	if(_trace_atexit) {
		LOG();
	}

	handle_free(param);

	return(0);
}

/* **** */

static uint32_t soc_omap_mpu_ckctl(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_mpu_ref mpu = param;
	csx_ref csx = mpu->csx;

	uint32_t data = write ? *write : 0;

	if(write) {
		if(_trace_mmio_mpu) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
			LOG_START("ARM_INTHCK_SEL: %01u", BEXT(data, 14));
			_LOG_(", EN_DSPCK: %01u", BEXT(data, 13));
			_LOG_(", ARM_TIMXO: %01u", BEXT(data, 12));
			LOG_END(", DSPMMUDIV: %01u", mlBFEXT(data, 11, 10));
			LOG_START("TCDIV: %01u", mlBFEXT(data, 9, 8));
			_LOG_(", DSPDIV: %01u", mlBFEXT(data, 7, 6));
			_LOG_(", ARMDIV: %01u", mlBFEXT(data, 5, 4));
			_LOG_(", LCDDIV: %01u", mlBFEXT(data, 3, 2));
			LOG_END(", ARM_PERDIV: %01u", mlBFEXT(data, 1, 0));
		}

		mpu->ckctl = data;
	} else
		return(mpu->ckctl);

	return(data);
}

static uint32_t soc_omap_mpu_idlct1(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_mpu_ref mpu = param;
	csx_ref csx = mpu->csx;

	uint32_t data = write ? *write : 0;

	if(write) {
		if(_trace_mmio_mpu) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
			LOG_START("IDL_CLKOUT_ARM: %01u", BEXT(data, 12));
			_LOG_(", WKUP_MODE: %01u", BEXT(data, 10));
			_LOG_(", IDLTIM_ARM: %01u", BEXT(data, 9));
			LOG_END(", IDLAPI_ARM: %01u", BEXT(data, 8));
			LOG_START("IDLDPLL_ARM: %01u", BEXT(data, 7));
			_LOG_(", IDLIF_ARM: %01u", BEXT(data, 6));
			_LOG_(", IDLPER_ARM: %01u", BEXT(data, 2));
			_LOG_(", IDLXOPR_ARM: %01u", BEXT(data, 1));
			LOG_END(", IDLWDT_ARM: %01u", BEXT(data, 0));
		}

		mpu->idlct[0] = data;
	} else
		return(mpu->idlct[0]);

	return(data);
}

static uint32_t soc_omap_mpu_idlct2(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_mpu_ref mpu = param;
	csx_ref csx = mpu->csx;

	uint32_t data = write ? *write : 0;

	if(write) {
		if(_trace_mmio_mpu) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
			LOG_START("EN_CKOUT_ARM: %01u", BEXT(data, 11));
			_LOG_(", DMACK_REQ: %01u", BEXT(data, 8));
			_LOG_(", EN_TIMCK: %01u", BEXT(data, 7));
			LOG_END(", EN_APICK: %01u", BEXT(data, 6));
			LOG_START("EN_LCDCK: %01u", BEXT(data, 3));
			_LOG_(", EN_PERCK: %01u", BEXT(data, 2));
			_LOG_(", EN_XORPCK: %01u", BEXT(data, 1));
			LOG_END(", EN_WDTCK: %01u", BEXT(data, 0));
		}

		mpu->idlct[1] = data;
	} else
		return(mpu->idlct[1]);

	return(data);
}

static uint32_t soc_omap_mpu_rstct2(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_mpu_ref mpu = param;
	csx_ref csx = mpu->csx;

	uint32_t data = write ? *write : 0;

	if(write) {
		if(_trace_mmio_mpu) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
			LOG("PER_EN: %01u", BEXT(data, 0));
		}

		mpu->rstct[1] = data;
	} else
		return(mpu->rstct[1]);

	return(data);
}

static uint32_t soc_omap_mpu_sysst(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_mpu_ref mpu = param;
	csx_ref csx = mpu->csx;

	uint32_t data = write ? *write : 0;

	if(write) {
		if(_trace_mmio_mpu) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
			LOG_START("CLOCK_SELECT: %01u", mlBFEXT(data, 13, 11));
			_LOG_(", IDLE_DSP: %01u", BEXT(data, 6));
			_LOG_(", POR: %01u", BEXT(data, 5));
			LOG_END(", EXT_RST: %01u", BEXT(data, 4));
			LOG_START("ARM_MCRST: %01u", BEXT(data, 3));
			_LOG_(", ARM_WDRST: %01u", BEXT(data, 2));
			_LOG_(", GLOB_SWRST: %01u", BEXT(data, 1));
			LOG_END(", DSP_WDRST: %01u", BEXT(data, 0));
		}
		data &= ~mlBF(5, 0);

		mpu->sysst = data;
	} else
		return(mpu->sysst);

	return(data);
}

static csx_mmio_access_list_t _soc_omap_mpu_acl[] = {
	SOC_MMIO_MPU_LIST(MMIO_TRACE_FN)
	{ .ppa = ~0U, },
};

soc_omap_mpu_ptr soc_omap_mpu_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_href h2mpu)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2mpu);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_omap_mpu_ref mpu = handle_calloc((void**)h2mpu, 1, sizeof(soc_omap_mpu_t));
	ERR_NULL(mpu);

	mpu->csx = csx;
	mpu->mmio = mmio;

	/* **** */

	csx_mmio_callback_atexit(mmio, &mpu->atexit, __soc_omap_mpu_atexit, h2mpu);

	/* **** */

	return(mpu);
}

void soc_omap_mpu_init(soc_omap_mpu_ref mpu)
{
	ERR_NULL(mpu);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_mmio_register_access_list(mpu->mmio, 0, _soc_omap_mpu_acl, mpu);
}
