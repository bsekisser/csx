#pragma once

/* **** */

typedef struct soc_mmu_t** soc_mmu_h;
typedef struct soc_mmu_t* soc_mmu_p;

/* **** */

#include "soc.h"

//#include "csx_soc.h"
#include "csx.h"

/* **** */

soc_mmu_p soc_mmu_alloc(csx_p csx, csx_soc_p soc, soc_mmu_h h2mmu);
void csx_mmu_dump_ttbr0(csx_p csx);
uint32_t csx_mmu_ifetch(csx_p csx, uint32_t va, size_t size);
uint32_t csx_mmu_read(csx_p csx, uint32_t va, size_t size);
void csx_mmu_write(csx_p csx, uint32_t va, size_t size, uint32_t data);
void soc_mmu_init(soc_mmu_p mmu);
int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* ppa);
