#pragma once

/* **** */

#include "csx.h"

/* **** */

enum {
	arm_v4,
	arm_v4t = 1,
	arm_v5t = 1,
	arm_v5te = 2,
	arm_v5texp = 2,
	arm_v5tej,
	arm_v6,
};

/* **** */

void soc_core_arm_step(soc_core_p core);
