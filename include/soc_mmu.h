#pragma once

/* **** */

typedef struct soc_mmu_t** soc_mmu_h;
typedef struct soc_mmu_t* soc_mmu_p;

/* **** */

#include "csx.h"

/* **** */

uint32_t csx_mmu_ifetch(csx_p csx, uint32_t va, size_t size);
uint32_t csx_mmu_ifetch_ma(csx_p csx, uint32_t va, size_t size);
uint32_t csx_mmu_read(csx_p csx, uint32_t va, size_t size);
uint32_t csx_mmu_read_ma(csx_p csx, uint32_t va, size_t size);
void csx_mmu_write(csx_p csx, uint32_t va, uint32_t data, size_t size);
void csx_mmu_write_ma(csx_p csx, uint32_t va, uint32_t data, size_t size);
int soc_mmu_init(csx_p csx, soc_mmu_h h2mmu);
int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* ppa);
