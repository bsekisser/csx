#pragma once

/* **** */

typedef struct csx_t* csx_p;
typedef struct csx_t** csx_h;

typedef struct csx_data_t* csx_data_p;

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
#include "soc_tlb.h"

#include "csx_state.h"

/* **** */

#define CSX_FRAMEBUFFER_BASE	0x20000000
#define CSX_FRAMEBUFFER_STOP	0x2003e7ff
#define CSX_FRAMEBUFFER_SIZE	(CSX_FRAMEBUFFER_STOP - CSX_FRAMEBUFFER_BASE)

#define CSX_SDRAM_BASE			0x10000000
#define CSX_SDRAM_SIZE			Mb(16)
#define CSX_SDRAM_STOP			((CSX_SDRAM_BASE + CSX_SDRAM_SIZE) - 1)

#define Kb(_x)						((_x) * 1024)
#define Mb(_x)						(Kb(Kb(_x))) 

/* **** */

typedef struct csx_data_t {
		uint32_t					base;
		void*						data;
		uint32_t					size;
}csx_data_t;

typedef struct csx_t {
	soc_core_p						core;
//	soc_coprocessor_p				cp;
	soc_mmu_p						mmu;
	soc_mmio_p						mmio;
	soc_nnd_p						nnd;
	soc_tlb_p						tlb;
	
	uint64_t						cycle;
	csx_state_t						state;

	uint32_t						cr[15];
#define vCR(_x)						csx->cr[_x]

	csh								cs_handle;

	csx_data_p						cdp;
	csx_data_t						loader;
	csx_data_t						firmware;

	uint8_t							sdram[CSX_SDRAM_SIZE];
	uint8_t							frame_buffer[CSX_FRAMEBUFFER_SIZE];
}csx_t;

/* **** */

extern const int _arm_version;
extern const int _check_pedantic_mmio;
extern const int _check_pedantic_pc;

/* **** */
