#pragma once

/* **** */

typedef struct soc_core_t** soc_core_h;
typedef struct soc_core_t* soc_core_p;

typedef struct soc_core_inst_t** soc_core_inst_h;
typedef struct soc_core_inst_t* soc_core_inst_p;

typedef void (*soc_core_step_fn)(soc_core_p csx);

/* **** */

#include "csx.h"

#include "soc_core_arm.h"
#include "soc_core_reg.h"

/* **** */

#define DataAbort() \
	{ soc_core_disasm(core, IP, IR); LOG_ACTION(core->csx->state = CSX_STATE_HALT); }

#define DECODE_FAULT \
	{ soc_core_disasm(core, IP, IR); LOG_ACTION(core->csx->state = CSX_STATE_HALT); }

#define ILLEGAL_INSTRUCTION \
	{ soc_core_disasm(core, IP, IR); LOG_ACTION(core->csx->state = CSX_STATE_HALT); }

#define PrefetchAbort() \
	{ soc_core_disasm(core, IP, IR); LOG_ACTION(core->csx->state = CSX_STATE_HALT); }

#define UNDEFINED \
	{ soc_core_disasm(core, IP, IR); LOG_ACTION(core->csx->state = CSX_STATE_HALT); }

#define UNDEFINED_INSTRUCTION \
	{ soc_core_disasm(core, IP, IR); LOG_ACTION(core->csx->state = CSX_STATE_HALT); }

#define UNPREDICTABLE \
	{ soc_core_disasm(core, IP, IR); LOG_ACTION(core->csx->state = CSX_STATE_HALT); }

#define UNIMPLIMENTED \
	{ soc_core_disasm(core, IP, IR); LOG_ACTION(core->csx->state = CSX_STATE_HALT); }

enum	{
	rRD,
	rRN,
	rRM,
	rRS,
	rRSOP_C,
	rRSOP_V,
	rR_COUNT,
//
	rREA = rRSOP_V,
	rRN_OFFSET = rRSOP_C,
};

typedef struct soc_core_inst_t {
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
}soc_core_inst_t;

typedef struct soc_core_t {
	uint32_t			reg[16];
#define GPR(_x)			core->reg[_x]

#define CPSR			core->cpsr
	uint32_t			cpsr;
	uint32_t			*spsr;

	uint32_t			abt_reg[4];
	uint32_t			fiq_reg[9];
	uint32_t			irq_reg[4];
	uint32_t			svc_reg[4];
	uint32_t			und_reg[4];

#define SCIx			(&core->inst)
	soc_core_inst_t		inst;

	soc_core_step_fn	step;
	csx_p				csx;

	uint				trace:1;
}soc_core_t;

/* **** */

int soc_core_in_a_privaleged_mode(soc_core_p core);
int soc_core_init(csx_p csx, soc_core_h h2core);
void soc_core_reset(soc_core_p core);
