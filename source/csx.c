#include "csx.h"
#include "csx_core.h"

int main(void)
{
	int err;
	csx_t ccsx, *csx = &ccsx;
	
	_TRACE_ENABLE_(csx, ENTER);
	_TRACE_ENABLE_(csx, EXIT);
	_TRACE_(csx, ENTER);

	csx->cycle = 0;
	csx->state = CSX_STATE_HALT;
	
	ERR(err = csx_core_init(csx));

//	csx_reg_set(csx, rPC, 0x2b5);
	
	if(!err)
	{
		csx->state = CSX_STATE_RUN;
		
		int limit = 32768;
		for(int i = 0; i < limit; i++)
		{
			csx->step(csx->core);

			if(csx->state & CSX_STATE_HALT)
				LOG_ACTION(break);
		}
	}

	LOG("0x%08x", csx_reg_get(csx->core, INSN_PC));

	_TRACE_(csx, EXIT);

	return(err);
}
