#pragma once

/* **** */

#include "soc_core_arm_decode.h"
#include "soc_core_reg.h"
#include "soc_core_trace.h"
#include "soc_core_utility.h"
#include "soc_core.h"

/* **** */

#include "csx_cp15_reg1.h"

/* **** */

#include "bitfield.h"
#include "shift_roll.h"

/* **** */

#include <assert.h>
#include <stdint.h>

/* **** */

static inline uint32_t ___ldr_x(soc_core_p core, soc_core_reg_t r, uint32_t ea)
{
	const unsigned v = soc_core_read(core, ea, sizeof(uint32_t));

	if(rPC == r)
		soc_core_reg_set_pcx(core, v);
	else
		soc_core_reg_set(core, r, v);

	return(v);
}

static inline void ___str_x(soc_core_p core, soc_core_reg_t r, uint32_t ea)
{
	_setup_rR_vR_src(core, rRD, r);
	soc_core_write(core, ea, sizeof(uint32_t), vR(D));
}

static inline void __ldr(soc_core_p core)
{
	const csx_p csx = core->csx;
	
	const unsigned ea_xx = vR(EA) & 3;
	
	if(ea_xx && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);
	
	vR(D) = soc_core_read(core, vR(EA), sizeof(uint32_t));

	if(ea_xx && CP15_reg1_bit(u))
		vR(D) = _ror(vR(D), (ea_xx << 3));

	if(rPC == rR(D)) {
		soc_core_reg_set_pcx(core, vR(D));
	} else
		soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __ldrb(soc_core_p core)
{
	vR(D) = (uint32_t)(uint8_t)soc_core_read(core, vR(EA), sizeof(uint8_t));
	
	soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __ldrd(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 3) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	unsigned ea = vR(EA);
	soc_core_reg_t r = rR(D);

	___ldr_x(core, r++, ea);
	ea += sizeof(uint32_t);
	vR(D) = ___ldr_x(core, r & 0x0f, ea);
}

static inline void __ldrh(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 1) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	vR(D) = (uint32_t)(uint16_t)soc_core_read(core, vR(EA), sizeof(uint16_t));
	
	soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __ldrsb(soc_core_p core)
{
	vR(D) = (uint32_t)((int32_t)(int8_t)soc_core_read(core, vR(EA), sizeof(int8_t)));

	soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __ldrsh(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 1) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	vR(D) = (uint32_t)((int32_t)(int16_t)soc_core_read(core, vR(EA), sizeof(uint16_t)));
	
	soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __str(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 3) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	_setup_rR_vR_src(core, rRD, rR(D));
	soc_core_write(core, vR(EA), sizeof(uint32_t), vR(D));
}

static inline void __strb(soc_core_p core)
{
	_setup_rR_vR_src(core, rRD, rR(D));
	soc_core_write(core, vR(EA), sizeof(uint8_t), (uint32_t)(uint8_t)vR(D));
}

static inline void __strd(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 3) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	unsigned ea = vR(EA);
	soc_core_reg_t r = rR(D);

	___str_x(core, r++, ea);
	ea += sizeof(uint32_t);
	___str_x(core, r & 0xf, ea);
}

static inline void __strh(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 1) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	_setup_rR_vR_src(core, rRD, rR(D));
	soc_core_write(core, vR(EA), sizeof(uint16_t), (uint32_t)(uint16_t)vR(D));
}

/* **** */

UNUSED_FN static void _arm_ldst(soc_core_p core)
{
	const unsigned flag_t = (!LDST_BIT(p24) && LDST_BIT(w21));
	
	_setup_rR_dst(core, rRD, ARM_IR_RD);

	if(CCx.e) {
		switch(LDST_BIT(l20) | (LDST_BIT(b22) << 1) | (flag_t << 2)) {
			case 0:
			case 4: /* strt */
				__str(core);
				break;
			case 1:
			case 5: /* ldrt */
				__ldr(core);
				break;
			case 2:
			case 6: /* strbt */
				__strb(core);
				break;
			case 3:
			case 7: /* ldrbt */
				__ldrb(core);
				break;
			default:
				LOG("p24: %01u, w21: %01u", LDST_BIT(p24), LDST_BIT(w21));
				UNIMPLIMENTED;
				break;
		}
	}
}

UNUSED_FN static void _arm_ldst_ea(soc_core_p core)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	unsigned wb_ea = vR(N);

	if(LDST_BIT(u23))
		wb_ea += vR(SOP);
	else
		wb_ea -= vR(SOP);

	if(CCx.e) {
		if((0 == LDST_BIT(p24)) || LDST_BIT(w21))
			soc_core_reg_set(core, rR(N), wb_ea);
	}

	vR(EA) = LDST_BIT(p24) ? wb_ea : vR(N);
}

UNUSED_FN static void _arm_ldst_sh(soc_core_p core)
{
	_setup_rR_dst(core, rRD, ARM_IR_RD);

#if 1
	const unsigned bwh = BMOV(IR, LDST_BIT_l20, 2) | mlBFEXT(IR, 6, 5);

	switch(bwh) {
		case 1:
			__strh(core);
			break;
		case 2:
			__ldrd(core);
			break;
		case 3:
			__strd(core);
			break;
		case 5:
			__ldrh(core);
			break;
		case 6:
			__ldrsb(core);
			break;
		case 7:
			__ldrsh(core);
			break;
		default:
			UNDEFINED;
			break;
	}
#else
	if(LDST_BIT(l20)) {
		if(LDST_BIT(s6)) {
			if(LDST_BIT(h5))
				__ldrsh(core);
			else
				__ldrsb(core);
		} else if(LDST_BIT(h5))
			__ldrh(core);
	} else {
		if(LDST_BIT(s6)) {
			if(LDST_BIT(h5))
				__strd(core);
			else
				__ldrd(core);
		} else
			__strh(core);
	}
#endif
}
