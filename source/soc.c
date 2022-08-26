#include "soc.h"
#include "soc_core.h"
#include "soc_core_cp15.h"
#include "csx.h"
#include "csx_state.h"

/* **** */

#include "bitfield.h"
#include "bounds.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define CYCLE csx->cycle

int csx_soc_init(csx_p csx)
{
	int err = 0;

	CYCLE = 0;
	
	ERR(err = soc_core_init(csx, &csx->core));
	ERR(err = soc_core_cp15_init(csx));
	ERR(err = soc_mmu_init(csx, &csx->mmu));
	ERR(err = soc_mmio_init(csx, &csx->mmio));
	
	return(err);
}

int csx_soc_main(int core_trace)
{
	int err = 0;
	csx_p csx = calloc(1, sizeof(csx_t));

	ERR_NULL(csx);
	if(!csx)
		return(-1);
	
	ERR(err = csx_soc_init(csx));
	csx_soc_reset(csx);

	const soc_core_p core = csx->core;

	core->trace = core_trace;

	if(!err)
	{
		csx->state = CSX_STATE_RUN;
		
		int limit = Mb(2) + Kb(0) + Kb(0);
		for(int i = 0; i < limit; i++)
		{
			csx->cycle++;

			core->step(core);

			if((csx->state & CSX_STATE_HALT) || (0 == PC))
			{
				i = limit;
				LOG_ACTION(break);
			}
		}
	}

	LOG("0x%08x", IP);

	return(err);
}

uint32_t csx_soc_read(csx_p csx, uint32_t va, size_t size)
{
	uint32_t data = 0;
	
	if(soc_mmu_read(csx->mmu, va, &data, size))
		;
	else if(_in_bounds(va, size, CSX_MMIO_BASE, CSX_MMIO_STOP))
		data = soc_mmio_read(csx->mmio, va, size);
	
	return(data);
}

void csx_soc_reset(csx_p csx)
{
	soc_core_reset(csx->core);
	soc_mmio_reset(csx->mmio);
}

void csx_soc_write(csx_p csx, uint32_t va, uint32_t data, size_t size)
{
	if(soc_mmu_write(csx->mmu, va, data, size))
		;
	else if(_in_bounds(va, size, CSX_MMIO_BASE, CSX_MMIO_STOP))
		soc_mmio_write(csx->mmio, va, data, size);
}
