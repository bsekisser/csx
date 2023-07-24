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

static inline uint32_t ___ldr_x(soc_core_p core, unsigned r, uint32_t ea)
{
	const unsigned v = soc_core_read(core, ea, sizeof(uint32_t));

	if(rPC == r)
		soc_core_reg_set_pcx(core, v);
	else
		soc_core_reg_set(core, r, v);

	return(v);
}

static inline void ___str_x(soc_core_p core, unsigned r, uint32_t ea)
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
	
	_setup_rR_dst(core, rRD, ARM_IR_RD);
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
	_setup_rR_dst(core, rRD, ARM_IR_RD);
	vR(D) = soc_core_read(core, vR(EA), sizeof(uint8_t));
	
	soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __ldrd(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 3) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	unsigned ea = vR(EA);
	
	_setup_rR_dst(core, rRD, ARM_IR_RD);
	unsigned r = rR(D);

	___ldr_x(core, r++, ea);
	ea += sizeof(uint32_t);
	vR(D) = ___ldr_x(core, r & 0x0f, ea);
}

static inline void __ldrh(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 1) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	_setup_rR_dst(core, rRD, ARM_IR_RD);
	vR(D) = soc_core_read(core, vR(EA), sizeof(uint16_t));
	
	soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __ldrsb(soc_core_p core)
{
	_setup_rR_dst(core, rRD, ARM_IR_RD);
	vR(D) = (int8_t)soc_core_read(core, vR(EA), sizeof(int8_t));

	soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __ldrsh(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 1) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	_setup_rR_dst(core, rRD, ARM_IR_RD);
	vR(D) = (int16_t)soc_core_read(core, vR(EA), sizeof(uint16_t));
	
	soc_core_reg_set(core, rR(D), vR(D));
}

static inline void __str(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 3) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	_setup_rR_vR_src(core, rRD, ARM_IR_RD);
	soc_core_write(core, vR(EA), sizeof(uint32_t), vR(D));
}

static inline void __strb(soc_core_p core)
{
	_setup_rR_vR_src(core, rRD, ARM_IR_RD);
	soc_core_write(core, vR(EA), sizeof(uint8_t), vR(D));
}

static inline void __strd(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 3) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	unsigned ea = vR(EA);
	unsigned r = ARM_IR_RD;

	___str_x(core, r++, ea);
	ea += sizeof(uint32_t);
	___str_x(core, r & 0xf, ea);
}

static inline void __strh(soc_core_p core)
{
	const csx_p csx = core->csx;

	if((vR(EA) & 1) && CP15_reg1_bit(a))
		soc_core_exception(core, _EXCEPTION_DataAbort);

	_setup_rR_vR_src(core, rRD, ARM_IR_RD);
	soc_core_write(core, vR(EA), sizeof(uint16_t), vR(D));
}

/* **** */

static inline void _arm_ldst_b(soc_core_p core)
{
	if(LDST_BIT(l20))
		__ldrb(core);
	else
		__strb(core);
}

static inline void _arm_ldst_w(soc_core_p core)
{
//	const csx_p csx = core->csx;

	if(LDST_BIT(l20))
		__ldr(core);
	else
		__str(core);
}

/* **** */

static void _arm_ldst(soc_core_p core)
{
	assert(LDST_BIT(p24) || (0 == LDST_BIT(w21)));
	assert(!((0 == LDST_BIT(p24)) && (1 == LDST_BIT_w21)));

	if(CCx.e) {
		if(LDST_BIT(b22))
			_arm_ldst_b(core);
		else
			_arm_ldst_w(core);
	}
}

static void _arm_ldst_ea(soc_core_p core)
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

static void _arm_ldst_sh(soc_core_p core)
{
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
