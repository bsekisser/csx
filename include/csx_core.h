#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "err_test.h"
#include "data.h"

#define UNPREDICTABLE

typedef struct csx_t* csx_p;

typedef uint8_t csx_reg_t;
typedef csx_reg_t* csx_reg_p;

typedef struct csx_core_t** csx_core_h;
typedef struct csx_core_t* csx_core_p;

typedef void (*csx_core_step_fn)(csx_core_p csx);

#include "csx_state.h"

#include "csx_core_arm.h"
#include "csx_core_arm_decode.h"
#include "csx_core_psr.h"
#include "csx_core_reg.h"
#include "csx_core_thumb.h"
#include "csx_core_trace.h"
#include "csx_core_utility.h"

typedef struct csx_core_t {
	uint32_t			reg[16];

	uint32_t			pc;

	uint32_t			cpsr;
	uint32_t			*spsr;

	uint32_t			abt_reg[4];
	uint32_t			fiq_reg[9];
	uint32_t			irq_reg[4];
	uint32_t			svc_reg[4];
	uint32_t			und_reg[4];

	csx_core_step_fn	step;
	csx_p				csx;

	CORE_T(const char*		ccs);
	T(uint32_t			trace_flags);
}csx_core_t;

static inline int csx_in_a_privaleged_mode(csx_core_p core)
{
	UNPREDICTABLE;
	if(0x00 != _bits(CPSR, 4, 0))
		return(1);
	else
		return(0);
}

/* csx_core.c */

const char* _arm_reg_name(csx_reg_t r);
int csx_core_init(csx_p csx, csx_core_h h2core);
