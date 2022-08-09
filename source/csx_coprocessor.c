#include "csx.h"
#include "csx_core.h"

typedef struct csx_coprocessor_t {
	csx_p csx;
	uint32_t creg[16];
}csx_coprocessor_t;

void csx_coprocessor_read(csx_p csx, csx_coproc_data_p acp)
{
	csx_core_p core = csx->core;
	csx_coprocessor_p cp = csx->cp;
	
	vR(N) = cp->creg[rR(N) & 0x0f];
	vR(D) = vR(N);
}

void csx_coprocessor_write(csx_p csx, csx_coproc_data_p acp)
{
	csx_core_p core = csx->core;
	csx_coprocessor_p cp = csx->cp;

	cp->creg[rR(N) & 0x0f] = vR(D);
}

int csx_coprocessor_init(csx_p csx)
{
	int err = 0;
	csx_coprocessor_p cp;
	
	ERR_NULL(cp = malloc(sizeof(csx_coprocessor_t)));
	
	csx->cp = cp;

	return(err);
}
