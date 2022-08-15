#include "csx_test_utility.h"

/* **** */

uint32_t pc(csx_test_p t)
{
	return(t->pc);
}

void _cxx(csx_test_p t, uint32_t value, uint8_t size)
{
	soc_mmu_write(t->csx->mmu, pc(t), value, size);
	t->pc += size;
}
