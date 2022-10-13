#pragma once

/* **** */

#include "csx.h"

/* **** */

#include "soc_core.h"
#include "soc_core_arm_decode.h"

/* **** */

void soc_core_trace_inst_dpi(soc_core_p core);
void soc_core_trace_inst_ldst(soc_core_p core, soc_core_ldst_p ls);
