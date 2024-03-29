#pragma once

/* **** */

#include <stdint.h>

/* **** */

typedef uint32_t csx_state_t;

/* **** */

#include "csx.h"

/* **** */

enum {
	CSX_STATE_HALT_BIT,
	CSX_STATE_RUN_BIT,
	CSX_STATE_INVALID_READ_BIT,
	CSX_STATE_INVALID_WRITE_BIT,
};

#define CSX_STATE_HALT				_BV(CSX_STATE_HALT_BIT)
#define CSX_STATE_RUN				_BV(CSX_STATE_RUN_BIT)
#define CSX_STATE_INVALID_READ		_BV(CSX_STATE_INVALID_READ_BIT)
#define CSX_STATE_INVALID_WRITE		_BV(CSX_STATE_INVALID_WRITE_BIT)
