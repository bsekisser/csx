#pragma once

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include <capstone/capstone.h>

#include "err_test.h"
#include "bitfield.h"
#include "bounds.h"
//#include "data.h"
#include "log.h"
#include "page.h"

#include "csx_trace.h"

/* **** */

extern const int _check_pedantic_pc;


/* **** */

typedef struct csx_t* csx_p;

#include "soc_core.h"
#include "soc_core_coprocessor.h"
#include "csx_mmio.h"
#include "csx_mmu.h"
#include "csx_state.h"

typedef struct csx_t {
	soc_core_p			core;
	soc_coprocessor_p	cp;
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

int csx_soc_init(csx_p csx);
uint32_t csx_soc_read(csx_p csx, uint32_t va, size_t size);
void csx_soc_write(csx_p csx, uint32_t va, uint32_t data, size_t size);
