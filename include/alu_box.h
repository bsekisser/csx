#include "soc_core_psr.h"

#include "csx.h"

/* **** */

#include "bitfield.h"
#include "shift_roll.h"
#include "unused.h"

/* **** */

#include <stdint.h>

/* **** */

typedef uint32_t (*alubox_fn)(soc_core_p core, uint32_t rn, uint32_t rm);

//#define __ALUBOX__INLINE__

#ifndef __ALUBOX__INLINE__
	#define __ALUBOX__INLINE__ inline
#endif

#ifndef __ALUBOX__STATIC__
	#define __ALUBOX__STATIC__ static
#endif

/* **** primary shift functions */

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t __alubox_asr_sop_c(soc_core_p core, uint32_t rm, uint32_t _rs) {
	const uint8_t rs = _rs & 0xff;
	uint32_t result = rm;

	if(rs)
		result = _asr_vc(rm, rs, (int32_t*)&vR(SOP_C));
	else
		vR(SOP_C) = BEXT(CPSR, SOC_CORE_PSR_BIT_C);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t __alubox_lsl_sop_c(soc_core_p core, uint32_t rm, uint32_t _rs) {
	const uint8_t rs = _rs & 0xff;
	uint32_t result = rm;
	
	if(rs)
		result = _lsl_vc(rm, rs, &vR(SOP_C));
	else
		vR(SOP_C) = BEXT(CPSR, SOC_CORE_PSR_BIT_C);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t __alubox_lsr_sop_c(soc_core_p core, uint32_t rm, uint32_t _rs) {
	const uint8_t rs = _rs & 0xff;
	uint32_t result = rm;

	if(rs)
		result = _lsr_vc(rm, rs, &vR(SOP_C));
	else
		vR(SOP_C) = BEXT(CPSR, SOC_CORE_PSR_BIT_C);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t __alubox_ror_sop_c(soc_core_p core, uint32_t rm, uint32_t _rs) {
	const uint8_t rs = _rs & 0xff;
	uint32_t result = rm;
	
	if(rs) {
		result = _ror_vc(rm, rs, &vR(SOP_C));
	} else {
		vR(SOP_C) = BEXT(CPSR, SOC_CORE_PSR_BIT_C);
	}

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t __alubox_rrx_sop_c(soc_core_p core, uint32_t rm, uint32_t _rs) {
	// TODO: untested!!
	const uint32_t result = _lsr(rm, 1) | BMOV(CPSR, SOC_CORE_PSR_BIT_C, 31);

	vR(SOP_C) = !!(rm & 1);

	return(result);

	UNUSED(_rs);
}


/* **** primary operational functions */

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_adc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn + rm + BEXT(CPSR, SOC_CORE_PSR_BIT_C));

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_adcs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_adc(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_add(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn + rm);

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_adds(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_add(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_and(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn & rm);

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_ands(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_and(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_bic(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn & ~rm);

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_bics(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_bic(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_eor(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn ^ rm);

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_eors(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_eor(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_mov(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(N));
#endif

	rR(N) = ~0;

	return(rm);

	UNUSED(rn);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_movs_asr(soc_core_p core, uint32_t rm, uint32_t _rs) {
	const uint8_t rs = _rs & 0xff;
	const uint32_t result = __alubox_asr_sop_c(core, rm, rs);

	if(rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	soc_core_flags_nz(core, result);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_movs_lsl(soc_core_p core, uint32_t rm, uint32_t _rs) {
	const uint8_t rs = _rs & 0xff;
	const uint32_t result = __alubox_lsl_sop_c(core, rm, rs);

	if(rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	soc_core_flags_nz(core, result);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_movs_lsr(soc_core_p core, uint32_t rm, uint32_t _rs) {
	const uint8_t rs = _rs & 0xff;
	const uint32_t result = __alubox_lsr_sop_c(core, rm, rs);

	if(rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	soc_core_flags_nz(core, result);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_movs_ror(soc_core_p core, uint32_t rm, uint32_t _rs) {
	const uint8_t rs = _rs & 0xff;
	const uint32_t result = __alubox_ror_sop_c(core, rm, rs);

	if(rs) {
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	soc_core_flags_nz(core, result);

	return(result);
}


UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_movs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_mov(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_mul(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn * rm);

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_muls(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_mul(core, rn, rm);

	soc_core_flags_nz(core, result);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_mvn(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(N));
#endif

	rR(N) = ~0;

	return(~rm);

	UNUSED(rn);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_mvns(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_mvn(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_orr(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn | rm);

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_orrs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_orr(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_rsb(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rm - rn);

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_rsbs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_rsb(core, rn, rm);
	
	soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_rsc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rm - (rn + BEXT(CPSR, SOC_CORE_PSR_BIT_C)));
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_rscs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_rsc(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_sbc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn - (rm + BEXT(CPSR, SOC_CORE_PSR_BIT_C)));
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_sbcs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_sbc(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__ __ALUBOX__INLINE__
uint32_t _alubox_sub(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn - rm);

	UNUSED(core);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_subs(soc_core_p core, uint32_t rn, uint32_t rm) {
	const uint32_t result = _alubox_sub(core, rn, rm);
	
	soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

/* **** secondary operational functions */

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_cmns(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(D));
#endif

	const uint32_t result = _alubox_add(core, rn, rm);
	
	soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_cmps(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(D));
#endif

	const uint32_t result = _alubox_sub(core, rn, rm);
	
	soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_teqs(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(D));
#endif

	const uint32_t result = _alubox_eor(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}

UNUSED_FN __ALUBOX__STATIC__
uint32_t _alubox_tsts(soc_core_p core, uint32_t rn, uint32_t rm) {
#ifdef _CHECK_PEDANTIC_INST_SBZ_
	assert(0 == rR(D));
#endif

	const uint32_t result = _alubox_and(core, rn, rm);

	soc_core_flags_nz(core, result);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));

	return(result);
}
