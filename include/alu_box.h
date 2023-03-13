#include "soc_core_psr.h"

#include "csx.h"

/* **** */

#include "bitfield.h"
#include "shift_roll.h"

/* **** */

#include <stdint.h>

/* **** */

typedef uint32_t (*alubox_fn)(soc_core_p core, uint32_t rn, uint32_t rm);


#ifndef STATIC
	#define STATIC static
#endif

STATIC uint32_t _alubox_adc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn + rm + BEXT(CPSR, SOC_CORE_PSR_BIT_C));

	UNUSED(core);
}

STATIC uint32_t _alubox_adcs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_adc(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

STATIC uint32_t _alubox_add(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn + rm);

	UNUSED(core);
}

STATIC uint32_t _alubox_adds(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_add(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

STATIC uint32_t _alubox_and(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn & rm);

	UNUSED(core);
}

STATIC uint32_t _alubox_ands(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_and(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

__attribute__((unused))
STATIC uint32_t _alubox_asrs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint8_t rs = rm & 0xff;
	const uint32_t result = _asr_c(rn, rs, (int*)&vR(SOP_C));

	if(rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	soc_core_flags_nz(core, result);

	return(result);
}

STATIC uint32_t _alubox_bic(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn & ~rm);

	UNUSED(core);
}

STATIC uint32_t _alubox_bics(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_bic(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

STATIC uint32_t _alubox_eor(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn ^ rm);

	UNUSED(core);
}

STATIC uint32_t _alubox_eors(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_eor(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

__attribute__((unused))
STATIC uint32_t _alubox_lsls(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint8_t rs = rm & 0xff;
	const uint32_t result = _lsl_c(rn, rs, (unsigned long int*)&vR(SOP_C));

	if(rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	soc_core_flags_nz(core, result);

	return(result);
}

__attribute__((unused))
STATIC uint32_t _alubox_lsrs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint8_t rs = rm & 0xff;
	const uint32_t result = _lsr_c(rn, rs, (unsigned long int*)&vR(SOP_C));

	if(rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	soc_core_flags_nz(core, result);

	return(result);
}

STATIC uint32_t _alubox_mov(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(N));
#endif

	rR(N) = ~0;

	return(rm);

	UNUSED(rn);
}

STATIC uint32_t _alubox_movs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_mov(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

__attribute__((unused))
STATIC uint32_t _alubox_mul(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn * rm);

	UNUSED(core);
}

__attribute__((unused))
STATIC uint32_t _alubox_muls(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_mul(core, rn, rm);

	soc_core_flags_nz(core, result);

	return(result);
}

STATIC uint32_t _alubox_mvn(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(N));
#endif

	rR(N) = ~0;

	return(~rm);

	UNUSED(rn);
}

STATIC uint32_t _alubox_mvns(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_mvn(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

STATIC uint32_t _alubox_orr(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn | rm);

	UNUSED(core);
}

STATIC uint32_t _alubox_orrs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_orr(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

__attribute__((unused))
STATIC uint32_t _alubox_rors(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint8_t rs = rm & 0xff;
	const uint32_t result = _ror(rn, rs);

	if(rs) {
		vR(SOP_C) = _lsr(rn, 32 - rs);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	soc_core_flags_nz(core, result);

	return(result);
}

STATIC uint32_t _alubox_rsb(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rm - rn);

	UNUSED(core);
}

STATIC uint32_t _alubox_rsbs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_rsb(core, rn, rm);
	
	soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

STATIC uint32_t _alubox_rsc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rm - (rn + BEXT(CPSR, SOC_CORE_PSR_BIT_C)));
}

__attribute__((unused))
STATIC uint32_t _alubox_rscs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_rsc(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

STATIC uint32_t _alubox_sbc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn - (rm + BEXT(CPSR, SOC_CORE_PSR_BIT_C)));
}

STATIC uint32_t _alubox_sbcs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_sbc(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

STATIC uint32_t _alubox_sub(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn - rm);

	UNUSED(core);
}

STATIC uint32_t _alubox_subs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_sub(core, rn, rm);
	
	soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

/* **** */

STATIC uint32_t _alubox_cmns(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(D));
#endif

	const uint32_t result = _alubox_add(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

STATIC uint32_t _alubox_cmps(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(D));
#endif

	const uint32_t result = _alubox_sub(core, rn, rm);
	
	soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

__attribute__((unused))
STATIC uint32_t _alubox_teqs(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(D));
#endif

	const uint32_t result = _alubox_eor(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

STATIC uint32_t _alubox_tsts(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(D));
#endif

	const uint32_t result = _alubox_and(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}
