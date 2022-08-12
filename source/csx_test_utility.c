#include "csx.h"
#include "soc_core.h"
#include "csx_test.h"

uint32_t pc(csx_test_p t)
{
	return(t->pc);
}

void _cxx(csx_test_p t, uint32_t value, uint8_t size)
{
	soc_mmu_write(t->csx->mmu, pc(t), value, size);
	t->pc += size;
}
