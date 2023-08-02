#pragma once

/* **** */

typedef void (*alubox_fn)(soc_core_p core, uint32_t* wb);

#include "alubox_flags.h"

/* **** */

#include "soc_core.h"

/* **** */

__ALUBOX_STATIC__
void _alubox_thumb_add(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) + vR(M);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_thumb_adds(soc_core_p core, uint32_t* wb)
{
	_alubox_thumb_add(core, wb);
	__alubox__flags__add_sop(core, vR(M));
}

__ALUBOX_STATIC__
void _alubox_thumb_adcs(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) + (vR(M) + BEXT_CPSR_F(C));

	if(wb)
		*wb = vR(D);

	__alubox__flags__add_sop(core, vR(M));
}

__ALUBOX_STATIC__
void _alubox_thumb_ands(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) & vR(M);

	if(wb)
		*wb = vR(D);

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_asrs(soc_core_p core, uint32_t* wb)
{
	int carry_out = 0;
	const unsigned valid_rs = vR(M) & 0xff;

	vR(D) = _asr_vc(vR(N), valid_rs, &carry_out);

	if(valid_rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, !!carry_out);

		if(wb)
			*wb = vR(D);
	}

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_bics(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) & ~vR(M);

	if(wb)
		*wb = vR(D);

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_eors(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) ^ vR(M);

	if(wb)
		*wb = vR(D);

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_lsls(soc_core_p core, uint32_t* wb)
{
	unsigned carry_out = 0;
	const unsigned valid_rs = vR(M) & 0xff;

	vR(D) = _lsl_vc(vR(N), valid_rs, &carry_out);

	if(valid_rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, !!carry_out);

		if(wb)
			*wb = vR(D);
	}

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_lsrs(soc_core_p core, uint32_t* wb)
{
	unsigned carry_out = 0;
	const unsigned valid_rs = vR(M) & 0xff;

	vR(D) = _lsr_vc(vR(N), valid_rs, &carry_out);

	if(valid_rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, !!carry_out);

		if(wb)
			*wb = vR(D);
	}

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_mov(soc_core_p core, uint32_t* wb)
{
	vR(D) = vR(M);

	if(wb)
		*wb = vR(D);
}

__ALUBOX_STATIC__
void _alubox_thumb_movs(soc_core_p core, uint32_t* wb)
{
	_alubox_thumb_mov(core, wb);
	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_muls(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) * vR(M);

	if(wb)
		*wb = vR(D);

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_mvns(soc_core_p core, uint32_t* wb)
{
	vR(D) = ~vR(M);

	if(wb)
		*wb = vR(D);

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_negs(soc_core_p core, uint32_t* wb)
{
	vR(D) = 0 - vR(M);

	if(wb)
		*wb = vR(D);

	__alubox__flags__add_sub(core, vR(D), 0, vR(M));
}


__ALUBOX_STATIC__
void _alubox_thumb_nop(soc_core_p core, uint32_t* wb)
{
	UNUSED(core, wb);
}

__ALUBOX_STATIC__
void _alubox_thumb_orrs(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) | vR(M);

	if(wb)
		*wb = vR(D);

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_rors(soc_core_p core, uint32_t* wb)
{
	const unsigned thumb_rors_4_0 = 1;

	const unsigned valid_rs_mask = thumb_rors_4_0 ? mlBF(4, 0) : mlBF(7, 0);
	const unsigned valid_rs = vR(M) & valid_rs_mask;

	unsigned carry_out = 0;
	vR(D) = _ror_vc(vR(N), valid_rs, &carry_out);

	if(valid_rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, !!carry_out);

		if(wb)
			*wb = vR(D);
	} else if(thumb_rors_4_0 && (0 != (vR(M) & 0xff))) {
		/* ???? is this actually correct ????
		 * 
		 * this looks to be the exact behavior as listed in the
		 * architectural reference manual.
		 */

		BMAS(CPSR, SOC_CORE_PSR_BIT_C, BEXT(vR(N), 31));
	}

	__alubox__flags_nz(core);
}

__ALUBOX_STATIC__
void _alubox_thumb_sbcs(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) - (vR(M) + !!(!BEXT_CPSR_F(C)));

	if(wb)
		*wb = vR(D);

	__alubox__flags__sub_sop(core, vR(M));
}

__ALUBOX_STATIC__
void _alubox_thumb_subs(soc_core_p core, uint32_t* wb)
{
	_setup_rR_vR_src(core, rRN, rR(N));
	vR(D) = vR(N) - vR(M);

	if(wb)
		*wb = vR(D);

	__alubox__flags__sub_sop(core, vR(M));
}

/* **** */

__ALUBOX_STATIC__
void _alubox_thumb_cmns(soc_core_p core, uint32_t* wb)
{
	_alubox_thumb_adds(core, 0);
	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_thumb_cmps(soc_core_p core, uint32_t* wb)
{
	_alubox_thumb_subs(core, 0);
	UNUSED(wb);
}

__ALUBOX_STATIC__
void _alubox_thumb_tsts(soc_core_p core, uint32_t* wb)
{
	_alubox_thumb_ands(core, 0);
	UNUSED(wb);
}
