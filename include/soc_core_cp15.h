#pragma once

/* **** */

#include "csx.h"

/* **** */

uint32_t soc_core_cp15_read(soc_core_p core);
void soc_core_cp15_write(soc_core_p core);
int soc_core_cp15_init(csx_p core);

enum {
	_cp15_reg1_a = 1,
	_cp15_reg1_m = 0,
	_cp15_reg1_u = 22,
};

#define CP15_reg1_bit(_x)				BEXT(vCR(1), _cp15_reg1_##_x)
#define CP15_reg1_set(_x)			BSET(vCR(1), _cp15_reg1_##_x)

#define CP15_reg1_Abit				CP15_reg1_bit(a)
#define CP15_reg1_Mbit				CP15_reg1_bit(m)
#define CP15_reg1_Ubit				CP15_reg1_bit(u)

//#define ARMv5_CP15_reg1_Ubit		((_arm_version >= arm_v5t) && CP15_reg1_bit(u))
#define ARMv5_CP15_reg1_Ubit		CP15_reg1_bit(u)
#define CP15_reg1_AbitOrUbit		(CP15_reg1_bit(a) || CP15_reg1_bit(u))

#define TTBR0						vCR(2)
