#pragma once

/* **** */

#include "alubox.h"
#include "soc_core.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */


__ALUBOX_STATIC__
void __alubox__flags_nz(soc_core_p core)
{
	const unsigned nf = BEXT(vR(D), 31);
	BMAS(CPSR, SOC_CORE_PSR_BIT_N, nf);

	const unsigned zf = (0 == vR(D));
	BMAS(CPSR, SOC_CORE_PSR_BIT_Z, zf);

	if(0) LOG("N: %01u, Z: %01u", nf, zf);
}

UNUSED_FN __ALUBOX_STATIC__
void __alubox__flags_nz_c(soc_core_p core)
{
//	BMAS(CPSR, SOC_CORE_PSR_BIT_C, !!vR(SOP_C));
	__alubox__flags_nz(core);
}

/*
 * Credit to:
 * 		http://www.emulators.com/docs/nx11_flags.htm
 *
 * OF(A+B) = ((A XOR D) AND NOT (A XOR B)) < 0
 * OF(A-B) = ((A XOR D) AND (A XOR B)) < 0
 *
 * CF(A+B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND NOT (A XOR B)) < 0)
 * CF(A-B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND (A XOR B)) < 0)
 *
 */

__ALUBOX_STATIC__
void __alubox__flags__add_sop(soc_core_p core, uint32_t sop)
{
	__alubox__flags_nz(core);

	const unsigned xvec = (vR(N) ^ sop);
	const unsigned ovec = (vR(N) ^ vR(D)) & ~xvec;

	const unsigned cf = BEXT((xvec ^ ovec ^ vR(D)), 31);
	BMAS(CPSR, SOC_CORE_PSR_BIT_C, cf);

	const unsigned vf = BEXT(ovec, 31);
	BMAS(CPSR, SOC_CORE_PSR_BIT_V, vf);

	if(0) LOG("sop: 0x%08x, C: %01u, V: %01u", sop, cf, vf);
}

UNUSED_FN __ALUBOX_STATIC__
void __alubox__flags__sub_sop(soc_core_p core, uint32_t sop)
{
	__alubox__flags__add_sop(core, ~sop);
}

UNUSED_FN __ALUBOX_STATIC__
void __alubox__flags_add(soc_core_p core)
{
	__alubox__flags__add_sop(core, vR(SOP_V));
}

UNUSED_FN __ALUBOX_STATIC__
void __alubox__flags_sub(soc_core_p core)
{
	__alubox__flags__sub_sop(core, vR(SOP_V));
}
