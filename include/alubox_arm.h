#pragma once

/* **** */

typedef void (*alubox_fn)(soc_core_p core);

#include "alubox_arm_shift.h"
#include "alubox_flags.h"

/* **** */

#include "soc_core.h"

/* **** */

#include "libbse/include/log.h"

/* **** */

__ALUBOX_STATIC__
void __alubox_arm__pc26_p(soc_core_p core)
{
	if(IF_CPSR_C(32))
		return;

	if(rPC != ARM_IR_RD)
		return;

	LOG_ACTION(assert(!IF_CPSR_C(32) && (rPC == ARM_IR_RD)));

	unsigned mask = SOC_CORE_PSR_NZCV;

	if(0 != (vR(D) & 3))
		mask = mlBF(32, 26) | 3;

	PC &= ~mask;
	PC |= vR(D) & mask;
}

__ALUBOX_STATIC__
void __alubox_arm__rN_sop(soc_core_p core)
{
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);
	__alubox_arm_shift_sop(core);
}

__ALUBOX_STATIC__
unsigned __alubox_arm__rN_sop_c(soc_core_p core)
{
	const unsigned carry_in = BEXT_CPSR_F(C);
	__alubox_arm__rN_sop(core);
	return(carry_in);
}

/* **** */

__ALUBOX_STATIC__
void _alubox_arm_adc(soc_core_p core)
{
	const unsigned carry_in = __alubox_arm__rN_sop_c(core);
	
	vR(D) = vR(N) + (vR(SOP) + carry_in);

	if(0) LOG("0x%08x + 0x%08x + %01u -- 0x%08x",
		vR(N), vR(SOP), carry_in, vR(D));
}

__ALUBOX_STATIC__
void _alubox_arm_add(soc_core_p core)
{
	__alubox_arm__rN_sop(core);

	vR(D) = vR(N) + vR(SOP);

	if(0) LOG("0x%08x + 0x%08x -- 0x%08x",
		vR(N), vR(SOP), vR(D));
}

__ALUBOX_STATIC__
void _alubox_arm_add_wb(soc_core_p core)
{
	_alubox_arm_add(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_adds_wb(soc_core_p core, unsigned wb)
{
	if(wb) {
		_alubox_arm_add_wb(core);
		if(rPC == rR(D))
			return;
	} else
		_alubox_arm_add(core);

	__alubox__flags_add(core);
}

__ALUBOX_STATIC__
void _alubox_arm_and(soc_core_p core)
{
	__alubox_arm__rN_sop(core);

	vR(D) = vR(N) & vR(SOP);
}

__ALUBOX_STATIC__
void _alubox_arm_and_wb(soc_core_p core)
{
	_alubox_arm_and(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_ands_wb(soc_core_p core, unsigned wb)
{
	if(wb) {
		_alubox_arm_and_wb(core);
		if(rPC == rR(D))
			return;
	} else
		_alubox_arm_and(core);

	__alubox_arm_shift_c(core);
	__alubox__flags_nz_c(core);
}

__ALUBOX_STATIC__
void _alubox_arm_bic(soc_core_p core)
{
	__alubox_arm__rN_sop(core);

	vR(D) = vR(N) & ~vR(SOP);
}

__ALUBOX_STATIC__
void _alubox_arm_eor(soc_core_p core)
{
	__alubox_arm__rN_sop(core);

	vR(D) = vR(N) ^ vR(SOP);
}

__ALUBOX_STATIC__
void _alubox_arm_eor_wb(soc_core_p core)
{
	_alubox_arm_eor(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_eors_wb(soc_core_p core, unsigned wb)
{
	if(wb) {
		_alubox_arm_eor_wb(core);
		if(rPC == rR(D))
			return;
	} else
		_alubox_arm_eor(core);

	__alubox_arm_shift_c(core);
	__alubox__flags_nz_c(core);
}

__ALUBOX_STATIC__
void _alubox_arm_mov(soc_core_p core)
{
	__alubox_arm_shift_sop(core);
	vR(D) = vR(SOP);
}

__ALUBOX_STATIC__
void _alubox_arm_mvn(soc_core_p core)
{
	__alubox_arm_shift_sop(core);
	vR(D) = ~vR(SOP);
}

__ALUBOX_STATIC__
void _alubox_arm_nop_xx(soc_core_p core)
{
	LOG_ACTION(exit(-1));
	UNUSED(core);
}

__ALUBOX_STATIC__
void _alubox_arm_orr(soc_core_p core)
{
	__alubox_arm__rN_sop(core);

	vR(D) = vR(N) | vR(SOP);
}

__ALUBOX_STATIC__
void _alubox_arm_rsb(soc_core_p core)
{
	__alubox_arm__rN_sop(core);

	vR(D) = vR(SOP) - vR(N);
}

__ALUBOX_STATIC__
void _alubox_arm_rsc(soc_core_p core)
{
	const unsigned carry_in = __alubox_arm__rN_sop_c(core);

	vR(D) = vR(SOP) - (vR(N) + !!(!carry_in));
}

__ALUBOX_STATIC__
void _alubox_arm_sbc(soc_core_p core)
{
	const unsigned carry_in = __alubox_arm__rN_sop_c(core);

	vR(D) = vR(N) - (vR(SOP) + !!(!carry_in));
}

__ALUBOX_STATIC__
void _alubox_arm_sub(soc_core_p core)
{
	__alubox_arm__rN_sop(core);

	vR(D) = vR(N) - vR(SOP);
}

__ALUBOX_STATIC__
void _alubox_arm_sub_wb(soc_core_p core)
{
	_alubox_arm_sub(core);
	
	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void _alubox_arm_subs_wb(soc_core_p core, unsigned wb)
{
	if(wb) {
		_alubox_arm_sub_wb(core);
		if(rPC == rR(D))
			return;
	} else
		_alubox_arm_sub(core);

	__alubox__flags_sub(core);
}

/* **** */

__ALUBOX_STATIC__
void alubox_arm_adc(soc_core_p core)
{
	_alubox_arm_adc(core);
	
	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void alubox_arm_adcs(soc_core_p core)
{
	alubox_arm_adc(core);

	if(rPC == rR(D))
		return;

	__alubox__flags_add(core);
}

__ALUBOX_STATIC__
void alubox_arm_add(soc_core_p core)
{
	_alubox_arm_add_wb(core);
}

__ALUBOX_STATIC__
void alubox_arm_adds(soc_core_p core)
{
	_alubox_arm_adds_wb(core, 1);
}

__ALUBOX_STATIC__
void alubox_arm_and(soc_core_p core)
{
	_alubox_arm_and_wb(core);
}

__ALUBOX_STATIC__
void alubox_arm_ands(soc_core_p core)
{
	_alubox_arm_ands_wb(core, 1);
}

__ALUBOX_STATIC__
void alubox_arm_bic(soc_core_p core)
{
	_alubox_arm_bic(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void alubox_arm_bics(soc_core_p core)
{
	alubox_arm_bic(core);

	if(rPC == rR(D))
		return;

	__alubox_arm_shift_c(core);
	__alubox__flags_nz_c(core);
}

UNUSED_FN __ALUBOX_STATIC__
void alubox_arm_cmnp(soc_core_p core)
{
	_alubox_arm_adds_wb(core, 0);
	__alubox_arm__pc26_p(core);
}

__ALUBOX_STATIC__
void alubox_arm_cmns(soc_core_p core)
{
	assert(0 == ARM_IR_RD); /* 1111 -- valid in 26-bit mode -- cmnp */

	_alubox_arm_adds_wb(core, 0);
}

UNUSED_FN __ALUBOX_STATIC__
void alubox_arm_cmpp(soc_core_p core)
{
	_alubox_arm_subs_wb(core, 0);
	__alubox_arm__pc26_p(core);
}

__ALUBOX_STATIC__
void alubox_arm_cmps(soc_core_p core)
{
	assert(0 == ARM_IR_RD); /* 1111 -- valid in 26-bit mode -- cmpp */

	_alubox_arm_subs_wb(core, 0);
}

__ALUBOX_STATIC__
void alubox_arm_eor(soc_core_p core)
{
	_alubox_arm_eor_wb(core);
}

__ALUBOX_STATIC__
void alubox_arm_eors(soc_core_p core)
{
	_alubox_arm_eors_wb(core, 1);
}

__ALUBOX_STATIC__
void alubox_arm_mov(soc_core_p core)
{
	_alubox_arm_mov(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void alubox_arm_movs(soc_core_p core)
{
	alubox_arm_mov(core);

	if(rPC == rR(D))
		return;

	__alubox_arm_shift_c(core);
	__alubox__flags_nz_c(core);
}

__ALUBOX_STATIC__
void alubox_arm_mvn(soc_core_p core)
{
	_alubox_arm_mvn(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void alubox_arm_mvns(soc_core_p core)
{
	alubox_arm_mvn(core);

	if(rPC == rR(D))
		return;

	__alubox_arm_shift_c(core);
	__alubox__flags_nz_c(core);
}

__ALUBOX_STATIC__
void alubox_arm_orr(soc_core_p core)
{
	_alubox_arm_orr(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void alubox_arm_orrs(soc_core_p core)
{
	alubox_arm_orr(core);

	if(rPC == rR(D))
		return;

	__alubox_arm_shift_c(core);
	__alubox__flags_nz_c(core);
}

__ALUBOX_STATIC__
void alubox_arm_rsb(soc_core_p core)
{
	_alubox_arm_rsb(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void alubox_arm_rsbs(soc_core_p core)
{
	alubox_arm_rsb(core);

	if(rPC == rR(D))
		return;

	__alubox__flags__add_sub(core, vR(D), vR(SOP), ~vR(N));
}

__ALUBOX_STATIC__
void alubox_arm_rsc(soc_core_p core)
{
	_alubox_arm_rsc(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void alubox_arm_rscs(soc_core_p core)
{
	alubox_arm_rsc(core);

	if(rPC == rR(D))
		return;

	__alubox__flags__add_sub(core, vR(D), vR(SOP), ~vR(N));
}

__ALUBOX_STATIC__
void alubox_arm_sbc(soc_core_p core)
{
	_alubox_arm_sbc(core);

	GPR(rR(D)) = vR(D);
}

__ALUBOX_STATIC__
void alubox_arm_sbcs(soc_core_p core)
{
	alubox_arm_sbc(core);

	if(rPC == rR(D))
		return;

	__alubox__flags_sub(core);
}

__ALUBOX_STATIC__
void alubox_arm_sub(soc_core_p core)
{
	_alubox_arm_sub_wb(core);
}

__ALUBOX_STATIC__
void alubox_arm_subs(soc_core_p core)
{
	_alubox_arm_subs_wb(core, 1);
}

UNUSED_FN __ALUBOX_STATIC__
void alubox_arm_teqp(soc_core_p core)
{
	_alubox_arm_eors_wb(core, 0);
	__alubox_arm__pc26_p(core);
}

__ALUBOX_STATIC__
void alubox_arm_teqs(soc_core_p core)
{
	assert(0 == ARM_IR_RD); /* 1111 -- valid in 26-bit mode -- teqp */
	
	_alubox_arm_eors_wb(core, 0);
}

UNUSED_FN __ALUBOX_STATIC__
void alubox_arm_tstp(soc_core_p core)
{
	_alubox_arm_ands_wb(core, 0);
	__alubox_arm__pc26_p(core);
}

__ALUBOX_STATIC__
void alubox_arm_tsts(soc_core_p core)
{
	assert(0 == ARM_IR_RD); /* 1111 -- valid in 26-bit mode -- tstp */

	_alubox_arm_ands_wb(core, 0);
}
