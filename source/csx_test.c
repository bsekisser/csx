#include "csx.h"
#include "csx_core.h"
#include "csx_test.h"

#include "csx_test_arm.h"
#include "csx_test_thumb.h"


uint32_t csx_test_run(csx_test_p t, uint32_t start_pc, uint32_t end_pc, uint32_t count)
{
	csx_p csx = t->csx;
	csx_core_p core = csx->core;

	if(0) LOG("start_pc = 0x%08x thumb = %u", start_pc, !!(CPSR & CSX_PSR_T));
	
	csx->state = CSX_STATE_RUN;
	
	uint32_t pc = start_pc;
	
	csx_reg_set(core, INSN_PC, pc);
	for(; count ; count--)
	{
		core->step(core);
	
		pc = csx_reg_get(core, TEST_PC);
		if(pc >= end_pc)
			break;
	}

	csx->state = CSX_STATE_HALT;

	return(pc);
}

int csx_soc_init(csx_p csx)
{
	int err;
	ERR(err = csx_core_init(csx, &csx->core));
	ERR(err = csx_mmu_init(csx, &csx->mmu));
	ERR(err = csx_mmio_init(csx, &csx->mmio));
	return(err);
}

int main(void)
{
	csx_t ccsx, *csx = &ccsx;
	csx_test_t test, *t = &test;

	_TRACE_ENABLE_(t, ENTER);
	_TRACE_ENABLE_(t, EXIT);
	_TRACE_(t, ENTER);
	
	t->csx = csx;
	csx->trace.head = 0;
	csx->trace.tail = 0;
	
	csx_soc_init(csx);

	t->start_pc = CSX_SDRAM_BASE;
	csx->cycle = 0;
	csx->state = CSX_STATE_HALT;
	
	_TRACE_(t, ENTER);
	
	if(0)
	{
		LOG("0 - 0x%08x, 1 - 0x%08x, 2 - 0x%08x", _BM(0), _BM1(0), _BM2(0));
		LOG("0 - 0x%08x, 1 - 0x%08x, 2 - 0x%08x", _BM(1), _BM1(1), _BM2(1));
		LOG("0 - 0x%08x, 1 - 0x%08x, 2 - 0x%08x", _BM(15), _BM1(15), _BM2(15));
		LOG("0 - 0x%08x, 1 - 0x%08x, 2 - 0x%08x", _BM(31), _BM1(31), _BM2(31));
	}

	csx_test_arm(t);
	csx_test_thumb(t);

	_TRACE_(t, EXIT);
}
