#pragma once

/* **** */

#include "csx.h"

/* **** */

uint32_t soc_core_cp15_read(soc_core_p core);
void soc_core_cp15_write(soc_core_p core);
int soc_core_cp15_init(csx_p core);
uint32_t soc_core_cp15(soc_core_p core, uint32_t* write);

enum {
	_CP15_CRn1_CRm0_OP2x0, /* control register */
	_CP15_CRn1_CRm0_OP2x1, /* auxiliarry control register */
	_CP15_CRn1_CRm0_OP2x2, /* coprocessor access control register */
//
	_CREG_COUNT,
};

enum {
	_CP15_CRn1_CRm0_OP2x0_a = 1,
	_CP15_CRn1_CRm0_OP2x0_m = 0,
	_CP15_CRn1_CRm0_OP2x0_v = 13,
	_CP15_CRn1_CRm0_OP2x0_u = 22,
	_CP15_CRn1_CRm0_OP2x0_ve = 24,
	_CP15_CRn1_CRm0_OP2x0_ee = 25,
};

#define CP15_reg1_bit(_x)			BEXT(_vCR(_CP15_CRn1_CRm0_OP2x0), _CP15_CRn1_CRm0_OP2x0_##_x)
#define CP15_reg1_clear(_x)			BCLR(_vCR(_CP15_CRn1_CRm0_OP2x0), _CP15_CRn1_CRm0_OP2x0_##_x)
#define CP15_reg1_set(_x)			BSET(_vCR(_CP15_CRn1_CRm0_OP2x0), _CP15_CRn1_CRm0_OP2x0_##_x)

#define CP15_reg1_AbitOrUbit		(CP15_reg1_bit(a) || CP15_reg1_bit(u))
