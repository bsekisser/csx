#include "csx.h"
#include "soc_core.h"
#include "csx_test.h"

#include "csx_test_arm.h"
#include "csx_test_thumb.h"
#include "csx_test_utility.h"


uint32_t _csx_test_run(csx_test_p t, uint32_t start_pc, uint32_t end_pc, uint32_t count)
{
	csx_p csx = t->csx;
	soc_core_p core = csx->core;

	if(0) LOG("start_pc = 0x%08x thumb = %u", start_pc, !!(CPSR & SOC_PSR_T));
	
	csx->state = CSX_STATE_RUN;
	
	soc_core_reg_set_pcx(core, start_pc);
	for(; count ; count--)
	{
		core->step(core);
	
		if(PC >= end_pc)
			break;
	}

	csx->state = CSX_STATE_HALT;

	return(PC);
}

uint32_t csx_test_run(csx_test_p t, uint32_t count)
{
	return(_csx_test_run(t, t->start_pc, pc(t), count));
}

uint32_t csx_test_run_thumb(csx_test_p t, uint32_t count)
{
	return(_csx_test_run(t, t->start_pc | 1, pc(t), count));
}

#if 0
int csx_soc_init(csx_p csx)
{
	int err;
	
	csx->cycle = 0;
	csx->trace.head = 0;
	csx->trace.tail = 0;
	
	ERR(err = soc_core_init(csx, &csx->core));
	ERR(err = soc_coprocessor_init(csx));
	ERR(err = soc_mmu_init(csx, &csx->mmu));
	ERR(err = soc_mmio_init(csx, &csx->mmio));
	
	soc_mmio_reset(csx->mmio);
	
	return(err);
}
#endif

int csx_test_main(void)
{
	csx_t ccsx, *csx = &ccsx;
	csx_test_t test, *t = &test;

	_TRACE_ENABLE_(t, ENTER);
	_TRACE_ENABLE_(t, EXIT);
	_TRACE_(t, ENTER);
	
	t->csx = csx;
	
	ERR(csx_soc_init(csx));

	t->start_pc = CSX_SDRAM_BASE;
	csx->state = CSX_STATE_HALT;
	
	_TRACE_(t, ENTER);
	
#if 0
	if(0)
	{
		LOG("0 - 0x%08x, 1 - 0x%08x, 2 - 0x%08x", _BM(0), _BM1(0), _BM2(0));
		LOG("0 - 0x%08x, 1 - 0x%08x, 2 - 0x%08x", _BM(1), _BM1(1), _BM2(1));
		LOG("0 - 0x%08x, 1 - 0x%08x, 2 - 0x%08x", _BM(15), _BM1(15), _BM2(15));
		LOG("0 - 0x%08x, 1 - 0x%08x, 2 - 0x%08x", _BM(31), _BM1(31), _BM2(31));
	}
#endif

	csx_test_arm(t);
	csx_test_thumb(t);

	_TRACE_(t, EXIT);
	
	return(0);
}
