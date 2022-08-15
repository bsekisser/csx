#include "soc_core_coprocessor.h"

/* **** */

#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_coprocessor_t {
	csx_p csx;
	uint32_t creg[16];
}soc_coprocessor_t;

void soc_coprocessor_read(csx_p csx, soc_coprocessor_p acp)
{
	soc_core_p core = csx->core;
	soc_coprocessor_p cp = csx->cp;
	
	vR(N) = cp->creg[rR(N) & 0x0f];
	vR(D) = vR(N);
}

void soc_coprocessor_write(csx_p csx, soc_coprocessor_p acp)
{
	soc_core_p core = csx->core;
	soc_coprocessor_p cp = csx->cp;

	cp->creg[rR(N) & 0x0f] = vR(D);
}

int soc_coprocessor_init(csx_p csx)
{
	int err = 0;
	soc_coprocessor_p cp;
	
	ERR_NULL(cp = malloc(sizeof(soc_coprocessor_t)));
	
	csx->cp = cp;

	return(err);
}
