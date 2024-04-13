#pragma once

/* **** */

extern const char* arm_dpi_op_string[16];
extern const char* condition_code_string[2][16];
extern const char* creg_name[16];
extern const char* reg_name[2][16];
extern const char* shift_op_string[2][6];

/* **** */

#include "config.h"

/* **** */

#include <assert.h>

/* **** */

#define rR_NAME(_x) _reg_name(rR(_x))
static inline const char* _reg_name(unsigned rr) {
	if(_check_pedantic_rname)
		assert((rr & 0x0f) == rr);

	return(reg_name[0][rr]);
}
