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
	_CP15_CRn2_CRm0_OP2x0, /* translation table base 0 */
	_CP15_CRn2_CRm0_OP2x1, /* translation table base 1 */
//
	_CP15_CRn3_CRm0_OP2x0, /* domain access control register */
//
	_CP15_CRn5_CRm0_OP2x0, /* combined / data fsr */
	_CP15_CRn5_CRm0_OP2x1, /* instruction fsr */
//
	_CREG_COUNT,
//
	_DACR = _CP15_CRn3_CRm0_OP2x0,
	_DFSR = _CP15_CRn5_CRm0_OP2x0,
	_IFSR = _CP15_CRn5_CRm0_OP2x1,
	_TTBR0 = _CP15_CRn2_CRm0_OP2x0,
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
#define CP15_reg1_set(_x)			BSET(_vCR(_CP15_CRn1_CRm0_OP2x0), _CP15_CRn1_CRm0_OP2x0_##_x)

#define CP15_reg1_Abit				CP15_reg1_bit(a)
#define CP15_reg1_EEbit				CP15_reg1_bit(ee)
#define CP15_reg1_Mbit				CP15_reg1_bit(m)
#define CP15_reg1_Ubit				CP15_reg1_bit(u)
#define CP15_reg1_VEbit				CP15_reg1_bit(ve)

//#define ARMv5_CP15_reg1_Ubit		((_arm_version >= arm_v5t) && CP15_reg1_bit(u))
#define ARMv5_CP15_reg1_Ubit		CP15_reg1_bit(u)
#define CP15_reg1_AbitOrUbit		(CP15_reg1_bit(a) || CP15_reg1_bit(u))

#define TTBCR						mmu->ttbcr
#define TTBR0						_vCR(_TTBR0)
