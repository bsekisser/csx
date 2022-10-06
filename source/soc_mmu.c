#include "soc_mmu.h"

#include "soc_core_cp15.h"
#include "soc_data.h"
#include "soc.h"

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
	uint32_t						ttbcr;
}soc_mmu_t;

typedef struct soc_mmu_ptd_t {
	uint ap:2;
	uint b:1;
	uint base:20;
	uint c:1;
	uint domain:4;
	uint type:2;
}soc_mmu_ptd_t;

/* **** */

soc_mmu_ptd_t _get_l1ptd(soc_mmu_p mmu, uint32_t va)
{
	const csx_p csx = mmu->csx;

	const int x = TTBCR & 7;

	const uint32_t l1ttb = mlBFTST(TTBR0, 31, 14 - x);
	const uint32_t va_ti = mlBFMOV(va, 31 - x, 20, 2);
	const uint32_t l1pta = l1ttb | va_ti;
	LOG("TTBR0 = 0x%08x, l1ttb = 0x%08x, va_ti = 0x%08x, l1pta = 0x%08x", TTBR0, l1ttb, va_ti, l1pta);

	const uint32_t l1ptd = csx_soc_read_ppa(csx, l1pta, sizeof(uint32_t), 1);
	LOG("l1ptd = 0x%08x, [1:0] = %01u", l1ptd, l1ptd & 3);

	static soc_mmu_ptd_t ptd;
	
	ptd.domain = mlBFEXT(l1ptd, 8, 5);
	ptd.type = l1ptd & 3;

	switch(ptd.type) {
		case 1: /* page */
			ptd.ap = 0;
			ptd.b = 0;
			ptd.base = mlBFTST(l1ptd, 31, 10);
			ptd.c = 0;

			LOG_START("Page Table Base Address(0x%08x)", ptd.base);
			_LOG_(": IMP(%01u)", BEXT(l1ptd, 9));
			_LOG_(": Domain(%01u)", ptd.domain);
			_LOG_(": SBO(%01u)", BEXT(l1ptd, 4));
			_LOG_(": ?(%01u)?", mlBFEXT(l1ptd, 3, 2));
			LOG_END(": 1(%01u)", mlBFEXT(l1ptd, 1, 0));
			break;
		case 2: /* page */
			ptd.ap = mlBFEXT(l1ptd, 11, 10);
			ptd.b = BEXT(l1ptd, 2);
			ptd.base = mlBFTST(l1ptd, 31, 20);
			ptd.c = BEXT(l1ptd, 3);

			LOG_START("Section Base Address(0x%08x)", ptd.base);
			_LOG_(": ?(0x%02x)", mlBFEXT(l1ptd, 19, 12));
			_LOG_(": AP(%02u)", ptd.ap);
			_LOG_(": IMP(%01u)", BEXT(l1ptd, 9));
			_LOG_(": Domain(%01u)", ptd.domain);
			_LOG_(": SBO(%01u)", BEXT(l1ptd, 4));
			_LOG_(": %c", ptd.c ? 'C' : 'c');
			_LOG_(": %c", ptd.b ? 'B' : 'b');
			LOG_END(": 2(%01u)", mlBFEXT(l1ptd, 1, 0));
			break;
		case 0: /* invalid */
		case 3: /* reserved -- ??? fine ??? */
			LOG_ACTION(exit(-1));
			break;
	}

	return(ptd);
}

/* **** */

int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* ppa)
{
	static int count = 1;
	const csx_p csx = mmu->csx;
	
	if(!CP15_reg1_Mbit || (-1 == TTBR0)) {
		*ppa = va;
		return(-1 == TTBR0);
	}

	const soc_mmu_ptd_t l1ptd = _get_l1ptd(mmu, va);

	switch(l1ptd.type) {
		case 2: {
			const uint32_t va_si = mlBFEXT(va, 19, 0);
			*ppa = l1ptd.base | va_si;
			LOG("l1_sba = 0x%08x, va_si = 0x%08x, ppa = 0x%08x",
				l1ptd.base, va_si, *ppa);
			return(1);
		} break;
		default:
			LOG_ACTION(exit(-1));
	}
	
	count--;
	if(0 >= count)
		LOG_ACTION(exit(-1));

	return(0);
}

int soc_mmu_init(csx_p csx, soc_mmu_h h2mmu)
{
	soc_mmu_p mmu = calloc(1, sizeof(soc_mmu_t));

	ERR_NULL(mmu);
	if(!mmu)
		return(-1);

	mmu->csx = csx;
	
	TTBR0 = -1;
	CP15_reg1_set(m);
	
	*h2mmu = mmu;

	return(0);
}

