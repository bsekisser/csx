#pragma once

/* **** */

typedef struct soc_nnd_t* soc_nnd_p;
typedef struct soc_nnd_t** soc_nnd_h;

/* **** */

#include "csx.h"

/* **** */

int soc_nnd_flash_init(csx_p csx, soc_nnd_h nnd);
uint32_t soc_nnd_flash_read(soc_nnd_p nnd, uint32_t addr, uint size);
void soc_nnd_flash_write(soc_nnd_p nnd, uint32_t addr, uint32_t value, uint size);

