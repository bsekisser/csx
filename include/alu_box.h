#pragma once

/* **** */

typedef uint32_t (*alubox_fn)(soc_core_p core, uint32_t rn, uint32_t rm);

/* **** */

#include "soc_core_psr.h"

#include "csx.h"

/* **** */

#include "bitfield.h"

/* **** */

#include <stdint.h>

/* **** */

#ifndef STATIC
	#define STATIC static
#endif

__attribute__((unused)) STATIC uint32_t _alubox_adc(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	return(rn + rm + BEXT(CPSR, SOC_CORE_PSR_BIT_C));

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_adcs(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_adc(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_add(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn + rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_adds(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_add(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_and(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn & rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_ands(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_and(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_asr(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(((int32_t)rn) >> rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_bic(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn & ~rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_bics(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_bic(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_eor(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn ^ rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_eors(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_eor(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_lsl(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn << rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_lsls_thumb_dp(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_lsl(core, rn, rm & 0xff);

	soc_core_flags_nz(core, result);

	if(rm) {
		CPSR &= ~SOC_CORE_PSR_C;

		if(rm < 32)
			CPSR |= BMOV(result, 32 - rm, SOC_CORE_PSR_BIT_C);
		else {
			if(32 == rm) {
				CPSR |= BMOV(result, 0, SOC_CORE_PSR_BIT_C);
			}
		}
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_lsr(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn >> rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_lsrs_thumb_dp(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_lsr(core, rn, rm & 0xff);
	uint32_t result_c = _alubox_lsr(core, rn, (rm - 1) & 0xff);

	soc_core_flags_nz(core, result);

	if(rm) {
		CPSR &= ~SOC_CORE_PSR_C;

		if(rm < 32)
			CPSR |= BMOV(result_c, 1, SOC_CORE_PSR_BIT_C);
		else {
			if(32 == rm) {
				CPSR |= BMOV(result, 31, SOC_CORE_PSR_BIT_C);
			}
		}
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_mov(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rm);

	(void)core; (void)rn;
}

__attribute__((unused)) STATIC uint32_t _alubox_mov_arm(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);
	assert(0 == rR(N));

	rR(N) = ~0;

	return(_alubox_mov(core, rn, rm));

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_movs(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_mov(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_movs_arm(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_mov_arm(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_mul(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn * rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_muls(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_mul(core, rn, rm);

	soc_core_flags_nz(core, result);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_mvn(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(~rm);

	(void)core; (void)rn;
}

__attribute__((unused)) STATIC uint32_t _alubox_mvn_arm(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);
	assert(0 == rR(N));

	rR(N) = ~0;

	return(_alubox_mvn(core, rn, rm));

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_mvns(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_mvn(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_mvns_arm(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_mvn_arm(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_null(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	LOG_ACTION(exit(-1));

	(void)core; (void)rn; (void)rm;
}

__attribute__((unused)) STATIC uint32_t _alubox_orr(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn | rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_orrs(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_orr(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_rsb(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rm - rn);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_rsbs(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_rsb(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_rsc(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	return(rm - (rn + BEXT(CPSR, SOC_CORE_PSR_BIT_C)));

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_rscs(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_rsc(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_ror(uint32_t rn, uint32_t rm) {
	return(_ror(rn, rm));
}

__attribute__((unused)) STATIC unsigned long int _alubox_ror_c(
	unsigned long int rn,
	unsigned long int rm,
	unsigned long int* carry)
{
	unsigned long int result = _alubox_ror(rn, rm);
	*carry = _lsr(rn, 32 - rm);

	return(result);
}

__attribute__((unused)) STATIC uint32_t _alubox_rors_thumb_dp(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	unsigned long int carry_out = 0;
	uint32_t result = _alubox_ror_c(rn, rm & 0xff, &carry_out);

	soc_core_flags_nz(core, result);

	CPSR &= ~SOC_CORE_PSR_C;
	
	if(carry_out)
		BSET(CPSR, SOC_CORE_PSR_BIT_C);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_sbc(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	return(rn - (rm + BEXT(CPSR, SOC_CORE_PSR_BIT_C)));

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_sbcs(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_sbc(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_sub(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn - rm);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_subs(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_sub(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);

	(void)core;
}

/* **** */

__attribute__((unused)) STATIC uint32_t _alubox_asrs_thumb_dp(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_asr(core, rn, rm & 0xff);
	uint32_t result_c = _alubox_lsr(core, rn, (rm - 1) & 0xff);

	soc_core_flags_nz(core, result);

	if(rm) {
		CPSR &= ~SOC_CORE_PSR_C;

		if(rm < 32)
			CPSR |= BMOV(result_c, 0, SOC_CORE_PSR_BIT_C);
		else {
			if(32 == rm) {
				CPSR |= BMOV(result, 31, SOC_CORE_PSR_BIT_C);
			}
			else {
				CPSR |= BMOV(0 != result, 0, SOC_CORE_PSR_BIT_C);
			}
		}
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_cmns(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);
	assert(0 == rR(D));

	uint32_t result = _alubox_add(core, rn, rm);
	
	if(CCx.e)
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_cmps(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);

	uint32_t result = _alubox_sub(core, rn, rm);
	
	if(CCx.e)
		soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_cmps_arm(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);
	assert(0 == rR(D));

	return(_alubox_cmps(core, rn, rm));

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_teqs(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);
	assert(0 == rR(D));

	uint32_t result = _alubox_eor(core, rn, rm);

	if(CCx.e) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}

__attribute__((unused)) STATIC uint32_t _alubox_tsts(soc_core_p core, uint32_t rn, uint32_t rm) {
	if(_check_pedantic_core)
		assert(0 != core);
	assert(0 == rR(D));

	uint32_t result = _alubox_and(core, rn, rm);

	if(CCx.e) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);

	(void)core;
}
