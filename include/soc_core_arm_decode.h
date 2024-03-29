#pragma once

/* **** */

#include "csx.h"

#include "soc_core_decode.h"

/* **** */

#define ARM_IR_CC mlBFEXT(IR, 31, 28)
#define ARM_IR_RD ((soc_core_reg_t)mlBFEXT(IR, 15, 12))
#define ARM_IR_RM ((soc_core_reg_t)mlBFEXT(IR, 3, 0))
#define ARM_IR_RN ((soc_core_reg_t)mlBFEXT(IR, 19, 16))
#define ARM_IR_RS ((soc_core_reg_t)mlBFEXT(IR, 11, 8))

#define ARM_IR_RDHi ARM_IR_RN
#define ARM_IR_RDLo ARM_IR_RD

enum {
	DPI_BIT_i25 = 25,
	DPI_BIT_s20 = 20,
	DPI_BIT_x4 = 4,
	DPI_BIT_x7 = 7,
};

#define DPI_BIT(_x)					BEXT(IR, DPI_BIT_##_x)
#define DPI_OPERATION				mlBFEXT(IR, 24, 21)
#define DPI_sOPERATION				mlBFEXT(IR, 24, 20)
#define DPI_SHIFT_OP				(DPI_BIT(i25) ? SOC_CORE_SHIFTER_OP_ROR : mlBFEXT(IR, 6, 5))
#define DPI_WB						(2 != mlBFEXT(IR, 24, 23))

enum {
	LDST_BIT_b22 = 22,
	LDST_BIT_h5 = 5,
	LDST_BIT_i22 = 22,
	LDST_BIT_l20 = 20,
	LDST_BIT_p24 = 24,
	LDST_BIT_u23 = 23,
	LDST_BIT_w21 = 21,
	LDST_BIT_s6 = 6,
	LDST_BIT_s22 = 22,
};

#define LDST_BIT(_x)				BEXT(IR, LDST_BIT_##_x)
#define LDST_FLAG_SH				((0 == LDSTX) && (0  != mlBFEXT(IR, 6, 5)))
#define LDST_FLAG_SH_I				(LDST_FLAG_SH && LDST_BIT(i22))
#define LDST_FLAG_S					(LDST_FLAG_SH && LDST_BIT(l20) && LDST_BIT(s6))
#define LDSTX						mlBFEXT(IR, 27, 25)


#define MCRC_CRm					ARM_IR_RM
#define MCRC_CRn					ARM_IR_RN
#define MCRC_CPx					mlBFEXT(IR, 11, 8)
#define MCRC_L						BEXT(IR, 20)
#define MCRC_OP1					mlBFEXT(IR, 23, 21)
#define MCRC_OP2					mlBFEXT(IR, 7, 5)
#define MCRC_Rd						ARM_IR_RD

/* **** */

void soc_core_arm_decode_coproc(soc_core_p core);
