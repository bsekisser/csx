#pragma once

/* **** */

#include <stdint.h>

/* **** */

typedef uint16_t shifter_operand_t;

/* **** */

#include "csx.h"

/* **** */

enum {
	SOC_CORE_SHIFTER_OP_LSL,
	SOC_CORE_SHIFTER_OP_LSR,
	SOC_CORE_SHIFTER_OP_ASR,
	SOC_CORE_SHIFTER_OP_ROR,
};
