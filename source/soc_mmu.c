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
	const csx_p csx = mmu->csx;
	static int double_fault = 0;
	
	if(double_fault)
		LOG_ACTION(exit(-1));

	*ppa = va;
	
	if(CP15_reg1_Mbit) {
		const uint32_t va_ti = mlBFMOV(va, 31, 20, 2);
		const uint32_t l1pta = mlBFTST(TTBR0, 31, 14) | va_ti;
		LOG("TTBR0 = 0x%08x, va_ti = 0x%08x, l1pta = 0x%08x", TTBR0, va_ti, l1pta);
		double_fault = 1;
		const uint32_t l1ptd = csx_soc_read(mmu->csx, l1pta | 2, sizeof(uint32_t));
		LOG("l1ptd = 0x%08x", l1ptd);
		double_fault = 0;
		const uint32_t va_si = mlBFEXT(va, 19, 0);
		const uint32_t l1_sba = mlBFTST(l1ptd, 31, 20);
		const uint32_t ppa = l1_sba | va_si;
		LOG("l1_sba = 0x%08x, va_si = 0x%08x, ppa = 0x%08x", l1_sba, va_si, ppa);
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

