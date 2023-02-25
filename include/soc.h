#pragma once

// TODO: transition soc to csx_soc

//typedef struct csx_t* csx_p;
typedef struct csx_soc_t** csx_soc_h;
typedef struct csx_soc_t* csx_soc_p;

/* **** */

#include "csx.h"

/* **** */

// TODO: soc_t from soc_omap_5912.h

typedef struct csx_soc_t {
	// TODO: sram
	// TODO: mmio modules

	csx_p csx;
	soc_p soc;
	
	callback_list_t atexit_list;
	callback_list_t atreset_list;
}csx_soc_t;

void csx_soc_callback_atexit(csx_soc_p soc, callback_fn fn, void* param);
void csx_soc_callback_atreset(csx_soc_p soc, callback_fn fn, void* param);

uint32_t csx_soc_ifetch(csx_p csx, uint32_t va, size_t size);
int csx_soc_init(csx_p csx, csx_soc_h h2soc);
int csx_soc_main(csx_p csx, int core_trace, int loader_firmware);
uint32_t csx_soc_read(csx_p csx, uint32_t va, size_t size);
uint32_t csx_soc_read_ppa(csx_p csx, uint32_t ppa, size_t size, void** src);
void csx_soc_reset(csx_p csx);
void csx_soc_write(csx_p csx, uint32_t va, uint32_t data, size_t size);
void csx_soc_write_ppa(csx_p csx, uint32_t ppa, uint32_t data, size_t size, void** dst);
