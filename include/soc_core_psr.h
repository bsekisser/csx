#pragma once

/* **** */

#include "csx.h"

/* **** */

enum {
	INST_CC_EQ = 0,
	INST_CC_NE,
	INST_CC_CSHS,
	INST_CC_CCLO,
	INST_CC_MI,
	INST_CC_PL,
	INST_CC_VS,
	INST_CC_VC,
	INST_CC_HI,
	INST_CC_LS,
	INST_CC_GE,
	INST_CC_LT,
	INST_CC_GT,
	INST_CC_LE,
	INST_CC_AL,
	INST_CC_NV
};

/* **** */

#define SOC_CORE_PSR_BIT_N		31
#define SOC_CORE_PSR_BIT_Z		30
#define SOC_CORE_PSR_BIT_C		29
#define SOC_CORE_PSR_BIT_V		28

#define SOC_CORE_PSR_BIT_Q		27
#define SOC_CORE_PSR_BIT_J		24
#define SOC_CORE_PSR_BIT_GE0		16
#define SOC_CORE_PSR_BIT_E		9
#define SOC_CORE_PSR_BIT_T		5

#define SOC_CORE_PSR_N			_BV(SOC_CORE_PSR_BIT_N)
#define SOC_CORE_PSR_Z			_BV(SOC_CORE_PSR_BIT_Z)
#define SOC_CORE_PSR_C			_BV(SOC_CORE_PSR_BIT_C)
#define SOC_CORE_PSR_V			_BV(SOC_CORE_PSR_BIT_V)

#define SOC_CORE_PSR_NZ			(SOC_CORE_PSR_N | SOC_CORE_PSR_Z)
#define SOC_CORE_PSR_NZC			(SOC_CORE_PSR_NZ | SOC_CORE_PSR_C)
#define SOC_CORE_PSR_NZCV		(SOC_CORE_PSR_NZC | SOC_CORE_PSR_V)

#define SOC_CORE_PSR_Q			_BV(SOC_CORE_PSR_BIT_Q)
#define SOC_CORE_PSR_E			_BV(SOC_CORE_PSR_BIT_E)
#define SOC_CORE_PSR_GE_MASK		(_BM(4) << SOC_CORE_PSR_BIT_GE0)
#define SOC_CORE_PSR_T			_BV(SOC_CORE_PSR_BIT_T)

#define SOC_CORE_PSR_MASK		(SOC_CORE_PSR_NZCV | SOC_CORE_PSR_Q | SOC_CORE_PSR_GE_MASK | SOC_CORE_PSR_E)

/* **** */

#define CPSR				core->cpsr
#define SPSR				core->spsr

/* function prototypes */

uint8_t soc_core_check_cc(soc_core_p core, uint8_t cond);

void soc_core_flags_nz(soc_core_p core, uint32_t rd_v);
void soc_core_flags_nzcv_add(soc_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v);
void soc_core_flags_nzcv_sub(soc_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v);
