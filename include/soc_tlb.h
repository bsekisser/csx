#pragma once

/* **** */

typedef struct soc_tlb_t** soc_tlb_h;
typedef struct soc_tlb_t* soc_tlb_p;

typedef struct soc_tlbe_t** soc_tlbe_h;
typedef struct soc_tlbe_t* soc_tlbe_p;


/* **** */

#include "csx.h"
#include "csx_mem.h"

/* **** */

void soc_tlb_fill_data_tlbe_read(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb);
void soc_tlb_fill_data_tlbe_write(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb);
void soc_tlb_fill_instruction_tlbe(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb);
csx_mem_callback_p soc_tlb_ifetch(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe);
int soc_tlb_init(csx_p csx, soc_tlb_h h2tlb);
void soc_tlb_invalidate_all(soc_tlb_p tlb);
void soc_tlb_invalidate_data(soc_tlb_p tlb);
void soc_tlb_invalidate_instruction(soc_tlb_p tlb);
csx_mem_callback_p soc_tlb_read(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe);
void soc_tlb_reset(soc_tlb_p tlb);
csx_mem_callback_p soc_tlb_write(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe);
