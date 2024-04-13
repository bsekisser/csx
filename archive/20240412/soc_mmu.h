#pragma once

/* **** */

typedef struct soc_mmu_t** soc_mmu_h;
typedef struct soc_mmu_t* soc_mmu_p;

/* **** */

#include "csx_soc.h"
#include "csx.h"

/* **** */

soc_mmu_p soc_mmu_alloc(csx_p csx, csx_soc_p soc, soc_mmu_h h2mmu);
void soc_mmu_dump_ttbr0(soc_mmu_p mmu);
uint32_t soc_mmu_ifetch(soc_mmu_p mmu, uint32_t va, size_t size);
void soc_mmu_init(soc_mmu_p mmu);
uint32_t soc_mmu_read(soc_mmu_p mmu, uint32_t va, size_t size);
int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* ppa);
void soc_mmu_write(soc_mmu_p mmu, uint32_t va, size_t size, uint32_t data);
