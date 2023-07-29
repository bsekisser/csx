#pragma once

/* **** */

#include "soc_core.h"

/* **** */

#include "unused.h"

/* **** */

#include <stdint.h>

/* **** */

static inline uint32_t __ldstm_ea(soc_core_p core, uint32_t* p2ea)
{
	const uint32_t ea = *p2ea;
	*p2ea += sizeof(uint32_t);

	return(ea);
	UNUSED(core);
}

/* **** */

static inline void __ldm(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __ldstm_ea(core, p2ea);
	
	GPR(r) = soc_core_read(core, ea, sizeof(uint32_t));
}

static inline void __ldm_pc(soc_core_p core, uint32_t* p2ea)
{
	const uint32_t ea = __ldstm_ea(core, p2ea);
	
	const uint32_t v = soc_core_read(core, ea, sizeof(uint32_t));

	if(_arm_version >= arm_v5t)
		soc_core_reg_set_pcx(core, v);
	else
		PC = v & (~3U >> BEXT_CPSR_C(Thumb));
}

static inline void __ldm_user(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __ldstm_ea(core, p2ea);
	
	uint32_t v = soc_core_read(core, ea, sizeof(uint32_t));
	soc_core_reg_usr(core, r, &v);
}

static inline void __stm(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __ldstm_ea(core, p2ea);
	
	soc_core_write(core, ea, sizeof(uint32_t), GPR(r));
}

static inline void __stm_user(soc_core_p core, soc_core_reg_t r, uint32_t* p2ea)
{
	const uint32_t ea = __ldstm_ea(core, p2ea);
	
	const uint32_t v = soc_core_reg_usr(core, r, 0);
	soc_core_write(core, ea, sizeof(uint32_t), v);
}

