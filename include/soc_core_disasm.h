#pragma once

/* **** */

#include "csx.h"

#include "soc_core.h"

/* **** */

void soc_core_disasm_arm(soc_core_p core, uint32_t address, uint32_t opcode);
void soc_core_disasm_thumb(soc_core_p core, uint32_t address, uint32_t opcode);
