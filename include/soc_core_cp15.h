#pragma once

/* **** */

/* **** */

#include "csx.h"

/* **** */

void soc_core_cp15_read(soc_core_p core);
void soc_core_cp15_write(soc_core_p core);
int soc_core_cp15_init(csx_p core);
