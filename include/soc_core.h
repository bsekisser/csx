#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "err_test.h"
//#include "data.h"

#define UNPREDICTABLE \
	TRACE("UNPREDICTABLE");

#define UNIMPLIMENTED \
	LOG_ACTION(exit(1));

#define ILLEGAL_INSTRUCTION \
	LOG_ACTION(exit(1));

typedef struct csx_t* csx_p;

typedef uint8_t soc_core_reg_t;
typedef soc_core_reg_t* soc_core_reg_p;

enum	{
	rRD,
	rRN,
	rRM,
	rRS,
	rR_COUNT
};

typedef struct soc_core_t** soc_core_h;
typedef struct soc_core_t* soc_core_p;

typedef void (*soc_core_step_fn)(soc_core_p csx);

typedef struct csx_inst_t {
	uint32_t					v[rR_COUNT];
#define vR(_x)					vRX(rR##_x)
#define vRX(_x)					SCIx->v[_x]

	uint32_t					ip;
#define IP						SCIx->ip
	uint32_t					ir;
#define IR						SCIx->ir

	soc_core_reg_t					r[rR_COUNT];
#define rR(_x)					rRX(rR##_x)
#define rRX(_x)					SCIx->r[_x]

	struct {
		const char*				s;
		int						e:1;
								}ccx;
#define CCx	SCIx->ccx
}csx_inst_t;

typedef struct soc_core_t {
	uint32_t			reg[16];

#define CPSR			core->cpsr
	uint32_t			cpsr;
	uint32_t			*spsr;

	uint32_t			abt_reg[4];
	uint32_t			fiq_reg[9];
	uint32_t			irq_reg[4];
	uint32_t			svc_reg[4];
	uint32_t			und_reg[4];

#define SCIx			(&core->inst)
	csx_inst_t			inst;

	soc_core_step_fn	step;
	csx_p				csx;

	T(uint32_t			trace_flags);
}soc_core_t;

#include "csx_state.h"

#include "soc_core_arm.h"
#include "soc_core_reg.h"

#include "soc_core_decode.h"
#include "soc_core_psr.h"
#include "soc_core_thumb.h"
#include "soc_core_trace.h"

static inline int csx_in_a_privaleged_mode(soc_core_p core)
{
//	UNPREDICTABLE;
	if(0x00 != mlBFEXT(CPSR, 4, 0))
		return(1);
	else
		return(0);
}

/* soc_core.c */

int soc_core_init(csx_p csx, soc_core_h h2core);
