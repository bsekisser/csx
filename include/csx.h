#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <capstone/capstone.h>

#include "err_test.h"
#include "bitfield.h"
//#include "data.h"

#include "csx_trace.h"

/* **** */

typedef struct csx_t* csx_p;

#include "csx_core.h"
#include "csx_core_coprocessor.h"
#include "csx_mmio.h"
#include "csx_mmu.h"
#include "csx_state.h"

typedef struct csx_t {
	csx_core_p			core;
	csx_coprocessor_p	cp;
	csx_mmu_p			mmu;
	csx_mmio_p			mmio;
	
	uint64_t			cycle;
	csx_state_t			state;

	struct {
		csx_trace_p		head;
		csx_trace_p		tail;
	}trace;
	
	T(uint32_t			trace_flags);
	
	csh					cs_handle;
}csx_t;

void csx_init(csx_p csx);
