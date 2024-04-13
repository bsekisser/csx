#pragma once

/* **** */

typedef struct csx_soc_exception_t** csx_soc_exception_h;
typedef struct csx_soc_exception_t* csx_soc_exception_p;

#include "arm_cpsr.h"

/* **** */

enum {
	_EXCEPTION_DataAbort,
	_EXCEPTION_FIQ,
	_EXCEPTION_IRQ,
	_EXCEPTION_PrefetchAbort,
	_EXCEPTION_Reset,
	_EXCEPTION_SWI,
	_EXCEPTION_UndefinedInstruction,
//
	_EXCEPTION_COUNT,
};

/* **** */

#include "soc_core.h"

/* **** */

#include "csx.h"

/* **** */

#define CSX_EXCEPTION(_x) csx_exception(csx, _EXCEPTION_##_x)
void csx_exception(csx_p csx, unsigned type);

csx_soc_exception_p csx_soc_exception_alloc(csx_p csx, csx_soc_exception_h h2cxu);
void csx_soc_exception_init(csx_soc_exception_p cxu);

/* **** */

#define SOC_CORE_EXCEPTION(_x) soc_core_exception(core, _EXCEPTION_##_x)
void soc_core_exception(soc_core_p core, unsigned type);
