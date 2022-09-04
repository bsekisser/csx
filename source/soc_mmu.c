#include "soc_mmu.h"

#include "soc_core_cp15.h"
#include "soc_data.h"

/* **** */

#include "bitfield.h"
#include "bounds.h"
#include "err_test.h"
#include "log.h"
#include "page.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_mmu_t* soc_mmu_p;
typedef struct soc_mmu_t {
	csx_p							csx;
}soc_mmu_t;

/* **** */

/* **** */

int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* ppa)
{
	csx_p csx = mmu->csx;

	*ppa = va;
	
	if(CP15_reg1_Mbit) {
		LOG_ACTION(exit(-1));
	}

	return(0);
}

int soc_mmu_init(csx_p csx, soc_mmu_h h2mmu)
{
	soc_mmu_p mmu = calloc(1, sizeof(soc_mmu_t));

	ERR_NULL(mmu);
	if(!mmu)
		return(-1);

	mmu->csx = csx;
	*h2mmu = mmu;

	return(0);
}

