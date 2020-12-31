#define UNPREDICTABLE

typedef struct csx_core_t* csx_core_p;

#include "csx_core_arm_decode.h"
#include "csx_core_psr.h"
#include "csx_core_reg.h"
#include "csx_core_thumb.h"
#include "csx_core_trace.h"
#include "csx_core_utility.h"

typedef struct csx_core_t {
	csx_p				csx;

	uint32_t			reg[16];

	uint32_t			pc;

	uint32_t			cpsr;
	uint32_t			spsr;

	uint32_t			abt_reg[4];
	uint32_t			fiq_reg[9];
	uint32_t			irq_reg[4];
	uint32_t			svc_reg[4];
	uint32_t			und_reg[4];

	T(const char*		ccs);
	T(uint32_t			trace_flags);
}csx_core_t;


static inline int csx_current_mode_has_spsr(csx_core_p core)
{
	UNPREDICTABLE;
	return(1);
}

static inline int csx_in_a_privaleged_mode(csx_core_p core)
{
	UNPREDICTABLE;
	if(0x00 != _bits(core->cpsr, 4, 0))
		return(1);
	else
		return(0);
}

/* csx_core.c */

int csx_core_init(csx_p csx);
