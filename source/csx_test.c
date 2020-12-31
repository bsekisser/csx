#include "csx.h"
#include "csx_core.h"
#include "csx_test.h"

#include "csx_test_arm.h"
//#include "csx_test_thumb.h"

void csx_test_run(csx_test_p t, uint32_t start_pc, uint32_t end_pc, uint32_t count)
{
	_TRACE_(t, ENTER);
	
	csx_p csx = t->csx;
	csx_core_p core = csx->core;
	
	csx->state = CSX_STATE_RUN;
	
	csx_reg_set(core, rPC, start_pc);
	do {
		csx->step(core);
		
		if(end_pc >= csx_reg_get(core, INSN_PC))
			break;
	}while(count--);

	csx->state = CSX_STATE_HALT;

	_TRACE_(t, EXIT);
}

int main(void)
{
	csx_test_t test, *t = &test;

	_TRACE_ENABLE_(t, ENTER);
	_TRACE_ENABLE_(t, EXIT);
	_TRACE_(t, ENTER);
	
	csx_core_init(t->csx);

	t->csx->cycle = 0;
	t->csx->state = CSX_STATE_HALT;
	
	_TRACE_(t, ENTER);
	
	csx_test_arm(t);

	_TRACE_(t, EXIT);
}
