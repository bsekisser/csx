#pragma once

/* **** */

/* **** */

#include "csx.h"

/* **** */

uint32_t soc_core_cp15_read(soc_core_p core);
void soc_core_cp15_write(soc_core_p core);
int soc_core_cp15_init(csx_p core);

#define CP15_reg1_Abit				BEXT(vCR(1), 1)
#define CP15_reg1_Ubit				BEXT(vCR(1), 22)

//#define ARMv5_CP15_reg1_Ubit		((_arm_version >= arm_v5t) && CP15_reg1_Ubit)
#define ARMv5_CP15_reg1_Ubit		CP15_reg1_Ubit
#define CP15_reg1_AbitOrUbit		(CP15_reg1_Abit || CP15_reg1_Ubit)
