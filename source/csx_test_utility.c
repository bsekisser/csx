#include "csx.h"
#include "csx_core.h"
#include "csx_test.h"

uint32_t pc(csx_test_p t)
{
	return(t->pc);
}

void _cxx(csx_test_p t, uint32_t value, uint8_t size)
{
	csx_mmu_write(t->csx->mmu, pc(t), value, size);
	t->pc += size;
}
