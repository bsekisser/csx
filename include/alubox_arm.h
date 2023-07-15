#pragma once

/* **** */

typedef void (*alubox_fn)(soc_core_p core, uint32_t* wb);

#include "alubox_arm_shift.h"
#include "alubox_flags.h"

/* **** */

#include "soc_core.h"

/* **** */

#include "log.h"

/* **** */

__ALUBOX_STATIC__
void _alubox_arm_adc(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	const unsigned carry_in = BEXT(CPSR, SOC_CORE_PSR_BIT_C);
	
	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) + (vR(SOP_V) + carry_in);

	if(0) LOG("0x%08x + 0x%08x + %01u -- 0x%08x",
		vR(N), vR(SOP_V), carry_in, vR(D));

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_adc_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_adc(core, wb);
	
	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_adcs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_adc_wb(core, wb);

	if(rPC != rR(D))
		__alubox__flags_add(core);
}

__ALUBOX_STATIC__
void _alubox_arm_add(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) + vR(SOP_V);

	if(0) LOG("0x%08x + 0x%08x -- 0x%08x",
		vR(N), vR(SOP_V), vR(D));

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_add_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_add(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_adds(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_add_wb(core, wb);

	if(rPC != rR(D))
		__alubox__flags_add(core);
}

__ALUBOX_STATIC__
void _alubox_arm_and(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) & vR(SOP_V);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_and_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_and(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_ands(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_and_wb(core, wb);

	if(rPC != rR(D)) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_bic(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) & ~vR(SOP_V);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_bic_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_bic(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_bics(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_bic_wb(core, wb);

	if(rPC != rR(D)) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_eor(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) ^ vR(SOP_V);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_eor_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_eor(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_eors(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_eor_wb(core, wb);

	if(rPC != rR(D)) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_mov(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(SOP_V);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_mov_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_mov(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_movs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_mov_wb(core, wb);

	if(rPC != rR(D)) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_mvn(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = ~vR(SOP_V);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_mvn_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_mvn(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_mvns(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_mvn_wb(core, wb);

	if(rPC != rR(D)) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_orr(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) | vR(SOP_V);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_orr_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_orr(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_orrs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_orr_wb(core, wb);

	if(rPC != rR(D)) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_rsb(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(SOP_V) - vR(N);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_rsb_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_rsb(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_rsbs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_rsb_wb(core, wb);

	if(rPC != rR(D))
		__alubox__flags_sub(core);
}

__ALUBOX_STATIC__
void _alubox_arm_rsc(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	const unsigned carry_in = BEXT(CPSR, SOC_CORE_PSR_BIT_C);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(SOP_V) - (vR(N) + carry_in);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_rsc_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_rsc(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_rscs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_rsc_wb(core, wb);

	if(rPC != rR(D))
		__alubox__flags_sub(core);
}

__ALUBOX_STATIC__
void _alubox_arm_sbc(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	const unsigned carry_in = BEXT(CPSR, SOC_CORE_PSR_BIT_C);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) - (vR(SOP_V) + carry_in);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_sbc_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_sbc(core, wb);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_sbcs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_sbc_wb(core, wb);

	if(rPC != rR(D))
		__alubox__flags_sub(core);
}

__ALUBOX_STATIC__
void _alubox_arm_sub(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) - vR(SOP_V);

	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_sub_wb(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_sub(core, wb);
	
	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_subs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_sub_wb(core, wb);

	if(rPC != rR(D))
		__alubox__flags_sub(core);
}

/* **** */

__ALUBOX_STATIC__
void _alubox_arm_cmns(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_adds(core, 0);
	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_cmps(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_subs(core, 0);
	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_teqs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_eors(core, 0);
	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_arm_tsts(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_ands(core, 0);
	UNUSED(wb);
}
