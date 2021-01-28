#include <assert.h>

#include "csx.h"
#include "csx_core.h"

int csx_soc_init(csx_p csx)
{
	int err;
	
	csx->cycle = 0;
	csx->trace.head = 0;
	csx->trace.tail = 0;
	
	ERR(err = csx_core_init(csx, &csx->core));
	ERR(err = csx_coprocessor_init(csx));
	ERR(err = csx_mmu_init(csx, &csx->mmu));
	ERR(err = csx_mmio_init(csx, &csx->mmio));
	
	csx_mmio_reset(csx->mmio);
	
	return(err);
}

#define Kb(_k) ((_k) * 1024)
#define Mb(_k) Kb((_k) * 1024)

int main(void)
{
	assert(0x01 == sizeof(uint8_t));
	assert(0x02 == sizeof(uint16_t));
	assert(0x04 == sizeof(uint32_t));
	assert(0x08 == sizeof(uint64_t));
	assert(~0UL == _BM(31));

	int err;
	csx_t ccsx, *csx = &ccsx;
	
	_TRACE_ENABLE_(csx, ENTER);
	_TRACE_ENABLE_(csx, EXIT);
	_TRACE_(csx, ENTER);


	ERR(err = csx_soc_init(csx));

//	csx_reg_set(csx, rPC, 0x2b5);
//	csx_reg_set(csx->core, rPC, CSX_SDRAM_BASE);
	
	if(!err)
	{
		csx->state = CSX_STATE_RUN;
		
		int limit = Mb(2) + Kb(0) + Kb(0);
		for(int i = 0; i < limit; i++)
		{
			csx_core_p core = csx->core;

			csx->cycle++;

			core->step(core);

			if(csx->state & CSX_STATE_HALT)
			{
				i = limit;
				LOG_ACTION(break);
			}
		}
	}

	LOG("0x%08x", csx->core->pc);

	_TRACE_(csx, EXIT);

	return(err);
}
