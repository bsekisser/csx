#pragma once

typedef struct csx_t* csx_p;

/* **** */

#include "csx.h"

/* **** */

uint32_t csx_soc_ifetch(csx_p csx, uint32_t va, size_t size);
int csx_soc_init(csx_p csx);
int csx_soc_main(int core_trace);
uint32_t csx_soc_read(csx_p csx, uint32_t va, size_t size);
void csx_soc_reset(csx_p csx);
void csx_soc_write(csx_p csx, uint32_t va, uint32_t data, size_t size);
