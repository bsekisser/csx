#pragma once

/* **** */

#include "soc_core.h"

/* **** */

#include "unused.h"

/* **** */

#include <stdint.h>

/* **** */

static uint32_t __arm_ldstm_ea(soc_core_p core, uint32_t* p2ea)
{
	const uint32_t ea = *p2ea;
	*p2ea += sizeof(uint32_t);

	return(ea);
	UNUSED(core);
}

static uint32_t __thumb_ldstm_ea(soc_core_p core, uint32_t* p2ea)
{
	const uint32_t ea = *p2ea;
	*p2ea += sizeof(uint32_t);

	return(ea);
	UNUSED(core);
}

/* **** */

static void __ldm(soc_core_p core, soc_core_reg_t r, uint32_t ea)
{
	GPR(r) = soc_core_read(core, ea, sizeof(uint32_t));
}

static void __ldm_pc(soc_core_p core, uint32_t ea)
{
	const uint32_t v = soc_core_read(core, ea, sizeof(uint32_t));

	if(_arm_version >= arm_v5t)
		soc_core_reg_set_pcx(core, v);
	else
		PC = v & (~3U >> BEXT_CPSR_C(Thumb));
}

static inline void __stm(soc_core_p core, soc_core_reg_t r, uint32_t ea)
{
	soc_core_write(core, ea, sizeof(uint32_t), GPR(r));
}

/* **** */

UNUSED_FN static
void _arm_ldm(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __arm_ldstm_ea(core, p2ea);
	__ldm(core, r, ea);
}

UNUSED_FN static
void _arm_ldm_pc(soc_core_p core, uint32_t* p2ea)
{
	const uint32_t ea = __arm_ldstm_ea(core, p2ea);
	__ldm_pc(core, ea);
}

UNUSED_FN static
void _arm_ldm_user(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __arm_ldstm_ea(core, p2ea);
	
	uint32_t v = soc_core_read(core, ea, sizeof(uint32_t));
	soc_core_reg_usr(core, r, &v);
}

UNUSED_FN static
void _arm_stm(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __arm_ldstm_ea(core, p2ea);
	__stm(core, r, ea);
}

UNUSED_FN static
void _arm_stm_user(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __arm_ldstm_ea(core, p2ea);
	
	const uint32_t v = soc_core_reg_usr(core, r, 0);
	soc_core_write(core, ea, sizeof(uint32_t), v);
}

/* **** */

UNUSED_FN static
void _thumb_ldm(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __thumb_ldstm_ea(core, p2ea);
	__ldm(core, r, ea);
}

UNUSED_FN static
void _thumb_ldm_pc(soc_core_p core, uint32_t* p2ea)
{
	const uint32_t ea = __thumb_ldstm_ea(core, p2ea);
	__ldm_pc(core, ea);
}

UNUSED_FN static
void _thumb_stm(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __thumb_ldstm_ea(core, p2ea);
	__stm(core, r, ea);
}
