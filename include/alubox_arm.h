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
	unsigned carry_in = !!BEXT(CPSR, SOC_CORE_PSR_BIT_C);
	
	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) + (vR(SOP_V) + carry_in);

	if(0) LOG("0x%08x + 0x%08x + %01u -- 0x%08x",
		vR(N), vR(SOP_V), carry_in, vR(D));

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_adcs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_adc(core, wb);

	if(CCx.e && (rPC != rR(D)))
		__alubox__flags_add(core);
}

__ALUBOX_STATIC__
void _alubox_arm_add(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) + vR(SOP_V);

	if(0) LOG("0x%08x + 0x%08x -- 0x%08x",
		vR(N), vR(SOP_V), vR(D));

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_adds(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_add(core, wb);

	if(CCx.e && (rPC != rR(D)))
		__alubox__flags_add(core);
}

__ALUBOX_STATIC__
void _alubox_arm_and(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) & vR(SOP_V);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_ands(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_and(core, wb);

	if(CCx.e && (rPC != rR(D))) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_bic(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) & ~vR(SOP_V);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_bics(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_bic(core, wb);

	if(CCx.e && (rPC != rR(D))) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_eor(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) ^ vR(SOP_V);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_eors(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_eor(core, wb);

	if(CCx.e && (rPC != rR(D))) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_mov(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(SOP_V);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_movs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_mov(core, wb);

	if(CCx.e && (rPC != rR(D))) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_mvn(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = ~vR(SOP_V);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_mvns(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_mvn(core, wb);

	if(CCx.e && (rPC != rR(D))) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_orr(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) | vR(SOP_V);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_orrs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_orr(core, wb);

	if(CCx.e && (rPC != rR(D))) {
		__alubox_arm_shift_c(core);
		__alubox__flags_nz_c(core);
	}
}

__ALUBOX_STATIC__
void _alubox_arm_rsb(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(SOP_V) - vR(N);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_rsbs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_rsb(core, wb);

	if(CCx.e && (rPC != rR(D)))
		__alubox__flags_sub(core);
}

__ALUBOX_STATIC__
void _alubox_arm_rsc(soc_core_p core, uint32_t* wb)
{
	unsigned carry_in = !!BEXT(CPSR, SOC_CORE_PSR_BIT_C);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(SOP_V) - (vR(N) + carry_in);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_rscs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_rsc(core, wb);

	if(CCx.e && (rPC != rR(D)))
		__alubox__flags_sub(core);
}

__ALUBOX_STATIC__
void _alubox_arm_sbc(soc_core_p core, uint32_t* wb)
{
	unsigned carry_in = !!BEXT(CPSR, SOC_CORE_PSR_BIT_C);

	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) - (vR(SOP_V) + carry_in);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_sbcs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_sbc(core, wb);

	if(CCx.e && (rPC != rR(D)))
		__alubox__flags_sub(core);
}

__ALUBOX_STATIC__
void _alubox_arm_sub(soc_core_p core, uint32_t* wb)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(N) - vR(SOP_V);

	if(CCx.e && wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_subs(soc_core_p core, uint32_t* wb)
{
	_alubox_arm_sub(core, wb);

	if(CCx.e && (rPC != rR(D)))
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
