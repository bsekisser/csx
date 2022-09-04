#pragma once

/* **** */

typedef struct soc_mmu_t** soc_mmu_h;
typedef struct soc_mmu_t* soc_mmu_p;

/* **** */
#include "csx.h"

/* **** */

int soc_mmu_init(csx_p csx, soc_mmu_h h2mmu);
int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* ppa);
