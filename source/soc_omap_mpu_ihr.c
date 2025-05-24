#include "soc_omap_mpu_ihr.h"

/* **** */
/* **** csx level includes */

#include "csx_data.h"
#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** local library includes */

#include "libbse/include/action.h"
#include "libbse/include/bitfield.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** system level includes*/

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_mpu_ihr_tag {
	struct {
		struct {
			uint32_t control;
			uint32_t enhanced_cntl;
			uint32_t isr;
			uint32_t itr;
			uint32_t mir;
			struct {
				uint32_t irq;
				uint32_t fiq;
			}sir;
			uint32_t ilr[32];
		}l1;
		struct {
			uint32_t control;
			uint32_t inth_rev;
			uint32_t ocp_cfg;
			struct {
				uint32_t irq;
				uint32_t fiq;
			}sir;
			uint32_t status;
			uint32_t itr[4];
			uint32_t mir[4];
			uint32_t ilr[4][32];
		}l2;
	};
//
	csx_ptr csx;
	csx_mmio_ptr mmio;
}soc_omap_mpu_ihr_t;

enum {
	_ITR,
	_MIR, // 0xffffffff
	_RESERVED_0x08,
	_RESERVED_0x0c,
	_SIR_IRQ,
	_SIR_FIQ,
	_CONTROL,
	_ILR0,
	_ISR = 0x9c,

	// l1 specific
	_L1_ENHANCED_CNTL = 0xa0,

	// l2 specific
	_L2_STATUS = 0xa0,
	_L2_OCP_CFG = 0xa4,
	_L2_INTH_REV = 0xa8,

};

#define ILRx(_x) ((_ILR0 << 2) + ((_x) << 2))
#define _ILRx(_x) (((_x & 0xff) - (_ILR0 << 2)) >> 2)

#define _L2_BANK(_x) (((_x & 0x3ff) >> 8) & 3)
#define SOC_OMAP_MPU_IHR_Lx_BANKx(_l, _b) \
	(SOC_OMAP_MPU_IHR_L ## _l + (((_b) & 3) << 8))

#define SOC_OMAP_MPU_IHR_Lx_BANKx_ILRx(_l, _b, _i) \
	(SOC_OMAP_MPU_IHR_Lx_BANKx(_l, _b) + ILRx(_i))

/* **** */

#define SOC_OMAP_MPU_IHR_L1_ACL(_MMIO) \
	_MMIO(_ITR, l1_itr, l1.itr) \
	_MMIO(_MIR, l1_mir, l1.mir) \
	_MMIO(_SIR_FIQ, l1_sir_fiq, l1.sir.fiq) \
	_MMIO(_SIR_IRQ, l1_sir_irq, l1.sir.irq) \
	_MMIO(_CONTROL, l1_control, l1.control) \
	_MMIO(_ISR, l1_isr, l1.isr) \
	_MMIO(_L1_ENHANCED_CNTL, l1_enhanced_cntl, l1.enhanced_cntl)

#define SOC_OMAP_MPU_IHR_L2_ACL0(_MMIO) \
	_MMIO(_SIR_FIQ, l2_sir_fiq, l2.sir.fiq) \
	_MMIO(_SIR_IRQ, l2_sir_irq, l2.sir.irq) \
	_MMIO(_CONTROL, l2_control, l2.control) \
	_MMIO(_L2_STATUS, l2_status, l2.status) \
	_MMIO(_L2_OCP_CFG, l2_ocp_cfg, l2.ocp_cfg) \
	_MMIO(_L2_INTH_REV, l2_inth_rev, l2.inth_rev)

#define SOC_OMAP_MPU_IHR_L2_BANKx_ACL(_MMIO) \
	_MMIO(_ITR, l2_itr, l2.itr[_L2_BANK(ppa)]) \
	_MMIO(_MIR, l2_mir, l2.mir[_L2_BANK(ppa)])

/* **** */

#define SOC_OMAP_MPU_IHR_MEM_ACCESS_VAR(_enum, _name, _var) \
	UNUSED_FN static uint32_t _soc_omap_mpu_ihr_ ## _name(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write) \
	{ \
		if(_check_pedantic_mmio_size) \
			assert(sizeof(uint32_t) == size); \
	\
		soc_omap_mpu_ihr_ref ihr = param; \
		csx_ref csx = ihr->csx; \
	\
		csx_data_target_t target = { \
			.base = &ihr->_var, \
			.offset = 0, \
			.size = sizeof(ihr->_var), \
		}; \
	\
		const uint32_t data = csx_data_target_mem_access(&target, size, write); \
	\
		if(_trace_mmio_mpu_ihr) { \
			CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data); \
		} \
	\
		return(data); \
	}

SOC_OMAP_MPU_IHR_L1_ACL(SOC_OMAP_MPU_IHR_MEM_ACCESS_VAR)
SOC_OMAP_MPU_IHR_MEM_ACCESS_VAR(_ILR0, l1_ilr, l1.ilr[_ILRx(ppa)])

SOC_OMAP_MPU_IHR_L2_ACL0(SOC_OMAP_MPU_IHR_MEM_ACCESS_VAR)
SOC_OMAP_MPU_IHR_L2_BANKx_ACL(SOC_OMAP_MPU_IHR_MEM_ACCESS_VAR)
SOC_OMAP_MPU_IHR_MEM_ACCESS_VAR(_ILR0, l2_ilr, l2.ilr[_L2_BANK(ppa)][_ILRx(ppa)])

/* **** */

#define SOC_OMAP_MPU_IHR_ACLE(_enum, _name, _var) \
	{ __MMIO_TRACE_FN((_enum << 2), 0, _enum, _soc_omap_mpu_ihr_ ## _name) },

static csx_mmio_access_list_t __soc_omap_mpu_ihr_l1_acl[] = {
	SOC_OMAP_MPU_IHR_L1_ACL(SOC_OMAP_MPU_IHR_ACLE)
	{ .ppa = ~0U, },
};

static csx_mmio_access_list_t __soc_omap_mpu_ihr_l2_acl[] = {
	SOC_OMAP_MPU_IHR_L2_ACL0(SOC_OMAP_MPU_IHR_ACLE)
	{ .ppa = ~0U, },
};

/* **** */

static
int soc_omap_mpu_ihr_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int soc_omap_mpu_ihr_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);
	ERR_NULL(param);

	soc_omap_mpu_ihr_ref ihr = param;

	/* **** */

	csx_mmio_ref mmio = ihr->mmio;
	ERR_NULL(mmio);

	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_IHR_L1, __soc_omap_mpu_ihr_l1_acl, ihr);

	for(unsigned i = 0; i < 32; i++) {
		const uint32_t ppa = SOC_OMAP_MPU_IHR_Lx_BANKx_ILRx(1, 0, i);
		csx_mmio_register_access(mmio, ppa, _soc_omap_mpu_ihr_l1_ilr, ihr);
	}

	csx_mmio_register_access_list(mmio, SOC_OMAP_MPU_IHR_L2, __soc_omap_mpu_ihr_l2_acl, ihr);

	for(unsigned j = 0; j <= 3; j++) {
		csx_mmio_access_list_t __soc_omap_mpu_ihr_l2x_acl[3] = {
			SOC_OMAP_MPU_IHR_L2_BANKx_ACL(SOC_OMAP_MPU_IHR_ACLE)
			{ .ppa = ~0U, },
		};

		csx_mmio_register_access_list(mmio,
			SOC_OMAP_MPU_IHR_Lx_BANKx(2, j),
			__soc_omap_mpu_ihr_l2x_acl, ihr);

		for(unsigned k = 0; k < 32; k++) {
			const uint32_t ppa = SOC_OMAP_MPU_IHR_Lx_BANKx_ILRx(2, j, k);

			csx_mmio_register_access(mmio, ppa, _soc_omap_mpu_ihr_l1_ilr, ihr);
		}
	}

	/* **** */

	return(err);
}

static
int soc_omap_mpu_ihr_action_reset(int err, void *const param, action_ref)
{
	ACTION_LOG(reset);

	soc_omap_mpu_ihr_ref ihr = param;

	/* **** */

	ihr->l1.mir = 0xffffffff;
	ihr->l2.mir[0] = 0xffffffff;
	ihr->l2.mir[1] = 0xffffffff;
	ihr->l2.mir[2] = 0xffffffff;
	ihr->l2.mir[3] = 0xffffffff;

	/* **** */

	return(err);
}

action_list_t soc_omap_mpu_ihr_action_list = {
	.list = {
		[_ACTION_EXIT] = {{ soc_omap_mpu_ihr_action_exit }, { 0 }, 0 },
		[_ACTION_INIT] = {{ soc_omap_mpu_ihr_action_init }, { 0 }, 0 },
		[_ACTION_RESET] = {{ soc_omap_mpu_ihr_action_reset }, { 0 }, 0 },
	}
};

/* **** */

soc_omap_mpu_ihr_ptr soc_omap_mpu_ihr_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_mpu_ihr_href h2ihr)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2ihr);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_mpu_ihr_ref ihr = handle_calloc(h2ihr, 1, sizeof(soc_omap_mpu_ihr_t));
	ERR_NULL(ihr);

	ihr->csx = csx;
	ihr->mmio = mmio;

	/* **** */

	return(ihr);
}
