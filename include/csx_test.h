#pragma once

/* **** */

typedef struct csx_test_t* csx_test_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct csx_test_t {
	csx_p			csx;
	
	uint32_t		start_pc;
	uint32_t		pc;
}csx_test_t;

/* **** */

int csx_test_main(csx_h h2csx, int core_trace);
uint32_t csx_test_run(csx_test_p t, uint32_t count);
uint32_t csx_test_run_thumb(csx_test_p t, uint32_t count);
