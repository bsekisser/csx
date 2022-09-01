#pragma once

/* **** */

typedef struct csx_t* csx_p;
typedef struct csx_t** csx_h;

/* **** */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/* **** */

#include <capstone/capstone.h>

/* **** */

#ifndef uint
	typedef unsigned int uint;
#endif

/* **** */

#include "soc_core.h"
//#include "soc_core_coprocessor.h"
#include "soc_mmu.h"
#include "soc_mmio.h"
#include "soc_nnd_flash.h"
#include "csx_state.h"

/* **** */

typedef struct csx_t {
	soc_core_p			core;
//	soc_coprocessor_p	cp;
	soc_mmu_p			mmu;
	soc_mmio_p			mmio;
	soc_nnd_p			nnd;
	
	uint64_t			cycle;
	csx_state_t			state;

	uint32_t			cr[15];
#define vCR(_x)			core->csx->cr[_x]

	csh					cs_handle;
}csx_t;

/* **** */

extern const int _arm_version;
extern const int _check_pedantic_mmio;
extern const int _check_pedantic_pc;

/* **** */

#define Kb(_x)						((_x) * 1024)
#define Mb(_x)						(Kb(Kb(_x))) 
