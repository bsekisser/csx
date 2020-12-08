#include "csx.h"

int main(void)
{
	int err;
	csx_t ccsx, *csx = &ccsx;
	
	err = csx_core_init(&csx);
	
	if(!err)
	{
		csx->state = CSX_STATE_RUN;
		
		int limit = 4096;
		for(int i = 0; i < limit; i++)
		{
			if(csx->state & CSX_STATE_HALT)
				break;
				
			csx_core_step(csx);
		}
	}

	return(err);
}
