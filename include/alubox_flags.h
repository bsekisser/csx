#pragma once

/* **** */

#include "alubox.h"
#include "soc_core.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */


__ALUBOX_STATIC__
void __alubox__flags_nz_x(soc_core_p core, uint32_t rd)
{
	const unsigned nf = BEXT(rd, 31);
	BMAS(CPSR, __CPSR_F(N), nf);

	const unsigned zf = (0 == rd);
	BMAS(CPSR, __CPSR_F(Z), zf);

	if(0) LOG("rd: 0x%08x, N: %01u, Z: %01u", rd, nf, zf);
}

__ALUBOX_STATIC__
void __alubox__flags_nz(soc_core_p core)
{
	__alubox__flags_nz_x(core, vR(D));
}

UNUSED_FN __ALUBOX_STATIC__
void __alubox__flags_nz_c(soc_core_p core)
{
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
void __alubox__flags__add_sub(soc_core_p core, uint32_t rd, uint32_t s1, uint32_t s2)
{
	__alubox__flags_nz(core);

	const unsigned xvec = (s1 ^ s2);
	const unsigned ovec = (s1 ^ rd) & ~xvec;

	const unsigned cf = BEXT((xvec ^ ovec ^ rd), 31);
	BMAS(CPSR, __CPSR_F(C), cf);

	const unsigned vf = BEXT(ovec, 31);
	BMAS(CPSR, __CPSR_F(V), vf);

	if(0) LOG("rd: 0x%08x, s1: 0x%08x, s2: 0x%08x, C: %01u, V: %01u",
		rd, s1, s2, cf, vf);
}

__ALUBOX_STATIC__
void __alubox__flags__add_sop(soc_core_p core, uint32_t sop)
{
	__alubox__flags__add_sub(core, vR(D), vR(N), sop);
}

UNUSED_FN __ALUBOX_STATIC__
void __alubox__flags__sub_sop(soc_core_p core, uint32_t sop)
{
	__alubox__flags__add_sop(core, ~sop);
}

UNUSED_FN __ALUBOX_STATIC__
void __alubox__flags_add(soc_core_p core)
{
	__alubox__flags__add_sop(core, vR(SOP));
}

UNUSED_FN __ALUBOX_STATIC__
void __alubox__flags_sub(soc_core_p core)
{
	__alubox__flags__sub_sop(core, vR(SOP));
}
