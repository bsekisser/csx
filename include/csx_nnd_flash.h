#pragma once

/* **** */

typedef struct csx_nnd_t* csx_nnd_p;
typedef struct csx_nnd_t** csx_nnd_h;

/* **** */

#include "csx.h"

/* **** */

csx_nnd_p csx_nnd_flash_alloc(csx_p csx, csx_nnd_h nnd);
void csx_nnd_flash_init(csx_nnd_p nnd);
uint32_t csx_nnd_flash_read(csx_nnd_p nnd, uint32_t addr, size_t size);
void csx_nnd_flash_write(csx_nnd_p nnd, uint32_t addr, size_t size, uint32_t value);

