#pragma once

typedef struct csx_t* csx_p;

/* **** */

#include "csx.h"

/* **** */

uint32_t csx_soc_ifetch(csx_p csx, uint32_t va, size_t size);
int csx_soc_init(csx_p csx);
int csx_soc_main(csx_p csx, int core_trace, int loader_firmware);
uint32_t csx_soc_read(csx_p csx, uint32_t va, size_t size);
uint32_t csx_soc_read_ppa(csx_p csx, uint32_t ppa, size_t size, void** src);
void csx_soc_reset(csx_p csx);
void csx_soc_write(csx_p csx, uint32_t va, uint32_t data, size_t size);
void csx_soc_write_ppa(csx_p csx, uint32_t ppa, uint32_t data, size_t size, void** dst);
