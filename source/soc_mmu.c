#include "soc_mmu.h"

#include "soc_core_cp15.h"
#include "soc_core_disasm.h"
#include "soc_core.h"
#include "soc.h"

/* **** */

#include "csx_data.h"
#include "csx_mem.h"

/* **** */

#include "bitfield.h"
#include "bounds.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"
#include "page.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_mmu_t* soc_mmu_p;
typedef struct soc_mmu_t { // TODO: move to header
	csx_p							csx;
	uint32_t						ttbcr;
	
	callback_list_t atexit_list;
	callback_list_t atreset_list;
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

static int _soc_mmu_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	soc_mmu_h h2mmu = param;
	soc_mmu_p mmu = *h2mmu;
	
	callback_list_process(&mmu->atexit_list);

	handle_free(param);
	
	return(0);
}

static int _soc_mmu_reset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	soc_mmu_p mmu = param;
	csx_p csx = mmu->csx;
	
	TTBCR = 0;
	TTBR0 = ~0U;
	CP15_reg1_set(m);

	callback_list_process(&mmu->atreset_list);

	return(0);
}

static soc_mmu_ptd_t _get_l1ptd(soc_mmu_p mmu, uint32_t va)
{
	const csx_p csx = mmu->csx;

	const int x = TTBCR & 7;

	const uint32_t l1ttb = mlBFTST(TTBR0, 31, 14 - x);
	const uint32_t va_ti = mlBFMOV(va, 31 - x, 20, 2);
	const uint32_t l1pta = l1ttb | va_ti;
	LOG("TTBR0 = 0x%08x, l1ttb = 0x%08x, va_ti = 0x%08x, l1pta = 0x%08x", TTBR0, l1ttb, va_ti, l1pta);

	const uint32_t l1ptd = csx_mem_access_read(csx, l1pta, sizeof(uint32_t), 0);
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

uint32_t csx_mmu_ifetch(csx_p csx, uint32_t va, size_t size)
{
	uint32_t ppa = va;
	csx_mem_callback_p src = 0;
	int tlb = 0;
	soc_tlbe_p tlbe = 0;

	if(CP15_reg1_Mbit) {
		src = soc_tlb_ifetch(csx->tlb, va, &tlbe);

		if(src)
			return(csx_mem_callback_read(src, va, size));

		tlb = soc_mmu_vpa_to_ppa(csx->mmu, va, &ppa);
	} 

	const uint32_t data = csx_mem_access_read(csx, ppa, size, &src);

	if(!src) {
		soc_core_p core = csx->core;
		PrefetchAbort();
	}

	if(tlb && src)
		soc_tlb_fill_instruction_tlbe(tlbe, va, src);

	return(data);
}

uint32_t csx_mmu_read(csx_p csx, uint32_t va, size_t size)
{
	uint32_t ppa = va;
	csx_mem_callback_p src = 0;
	int tlb = 0;
	soc_tlbe_p tlbe = 0;

	if(CP15_reg1_Mbit) {
		src = soc_tlb_read(csx->tlb, va, &tlbe);

		if(src)
			return(csx_mem_callback_read(src, va, size));

		tlb = soc_mmu_vpa_to_ppa(csx->mmu, va, &ppa);
	} 

	const uint32_t data = csx_mem_access_read(csx, ppa, size, &src);

	if(!src) {
		soc_core_p core = csx->core;
		DataAbort();
	}
	
	if(tlb && src)
		soc_tlb_fill_data_tlbe_read(tlbe, va, src);

	return(data);
}

void csx_mmu_write(csx_p csx, uint32_t va, size_t size, uint32_t data)
{
	uint32_t ppa = va;
	csx_mem_callback_p dst = 0;
	int tlb = 0;
	soc_tlbe_p tlbe = 0;

	if(CP15_reg1_Mbit) {
		dst = soc_tlb_write(csx->tlb, va, &tlbe);

		if(dst)
			return(csx_mem_callback_write(dst, va, size, &data));

		tlb = soc_mmu_vpa_to_ppa(csx->mmu, va, &ppa);
	}

	dst = csx_mem_access_write(csx, ppa, size, &data);

	if(!dst) {
		soc_core_p core = csx->core;
		DataAbort();
	}

	if(tlb && dst)
		soc_tlb_fill_data_tlbe_write(tlbe, va, dst);
}

int soc_mmu_init(csx_p csx, soc_mmu_h h2mmu)
{
	if(_trace_init) {
		LOG();
	}

	assert(0 != csx);
	assert(0 != h2mmu);
	
	soc_mmu_p mmu = HANDLE_CALLOC(h2mmu, 1, sizeof(soc_mmu_t));
	ERR_NULL(mmu);

	mmu->csx = csx;

	callback_list_init(&mmu->atexit_list, 0, LIST_LIFO);
	callback_list_init(&mmu->atreset_list, 0, LIST_FIFO);

	csx_callback_atexit(csx, _soc_mmu_atexit, h2mmu);
	csx_callback_atreset(csx, _soc_mmu_reset, mmu);

	return(0);
}

int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* ppa)
{
	static int count = 1;
	const csx_p csx = mmu->csx;

	if(!CP15_reg1_Mbit || (~0U == TTBR0)) {
		*ppa = va;
		return(~0U == TTBR0);
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
