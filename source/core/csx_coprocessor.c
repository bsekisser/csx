#include "csx.h"
#include "csx_core.h"

typedef struct csx_coprocessor_t {
	uint32_t creg[16];
}csx_coprocessor_t;

void csx_coprocessor_read(csx_p csx, csx_coproc_data_p acp)
{
	csx_coprocessor_p cp = csx->cp;
	
	acp->crn_v = cp->creg[acp->crn & 0x0f];
	acp->rd_v = acp->crn_v;
}

void csx_coprocessor_write(csx_p csx, csx_coproc_data_p acp)
{
	csx_coprocessor_p cp = csx->cp;

	cp->creg[acp->crn & 0x0f] = acp->rd_v;
}

int csx_coprocessor_init(csx_p csx)
{
	int err;
	csx_coprocessor_p cp;
	
	ERR_NULL(cp = malloc(sizeof(csx_coprocessor_t)));
	
	csx->cp = cp;

	return(0);
}
