#include "soc_mmu.h"

#include "soc_core_cp15.h"
#include "soc_core_disasm.h"
#include "soc_core.h"
#include "soc.h"

/* **** */

#include "exception.h"

#include "csx_data.h"
#include "csx_mem.h"
#include "csx.h"

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
	csx_soc_p						soc;

	uint32_t						ttbcr;

	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atexit;
		
	struct {
		callback_qlist_t list;
		callback_qlist_elem_t elem;
	}atreset;

	union {
		unsigned raw_flags;
		struct {
			unsigned debug:1;
		};
	};
}soc_mmu_t;

typedef struct soc_mmu_ptd_t* soc_mmu_ptd_p;
typedef struct soc_mmu_ptd_t {
	uint64_t base;

	unsigned raw;

	union {
		unsigned flags_raw;
		struct {
			unsigned ap:2;
			unsigned apx:1;
			unsigned b:1;
			unsigned c:1;
			unsigned domain:4;
			unsigned imp:1;
			unsigned is_supersection:1;
			unsigned ng:1;
			unsigned s:1;
			unsigned tex:3;
			unsigned type:2;
			unsigned xn:1;
		};
	};
}soc_mmu_ptd_t;


/* **** */

static int _soc_mmu_atexit(void* param)
{
	if(_trace_atexit) {
		LOG("<<");
	}

	soc_mmu_h h2mmu = param;
	soc_mmu_p mmu = *h2mmu;

	callback_qlist_process(&mmu->atexit.list);

	if(_trace_atexit_pedantic) {
		LOG("--");
	}

	handle_free(param);

	if(_trace_atexit_pedantic) {
		LOG("<<");
	}

	return(0);
}

static inline int _soc_mmu_l1ptd_02(soc_mmu_p mmu, soc_mmu_ptd_p ptd, uint32_t va, unsigned* p2ppa)
{
	ptd->ap = mlBFEXT(ptd->raw, 11, 10);
	ptd->apx = BEXT(ptd->raw, 15);
	ptd->b = BEXT(ptd->raw, 2);
	ptd->c = BEXT(ptd->raw, 3);
	ptd->imp = BEXT(ptd->raw, 9);
	ptd->is_supersection = BEXT(ptd->raw, 18);
	ptd->ng = BEXT(ptd->raw, 17);
	ptd->s = BEXT(ptd->raw, 16);
	ptd->tex = mlBFEXT(ptd->raw, 14, 12);
	ptd->xn = BEXT(ptd->raw, 4);

	ptd->domain = ptd->is_supersection ? 0 : mlBFEXT(ptd->raw, 8, 5);

	const unsigned sba_lsb = ptd->is_supersection ? 24 : 20;
	ptd->base = mlBFTST(ptd->raw, 31, sba_lsb);

	if(ptd->is_supersection) {
		ptd->base |= mlBFMOV(ptd->raw, 23, 20, 32);
		ptd->base |= mlBFMOV(ptd->raw, 8, 5, 36);
	}

	if(mmu->debug) {
		if(ptd->is_supersection) {
			LOG_START("Supersection Base Address: 0x%016llx", ptd->base);
		} else {
			LOG_START("Section Base Address: 0x%08llx", ptd->base);
		}

		_LOG_(":nG(%01u)", ptd->ng);
		_LOG_(":%c", ptd->s ? 'S' : 's');
		_LOG_(":APX(%01u)", ptd->apx);
		_LOG_(":TEX(%01u)", ptd->tex);
		_LOG_(":AP(%01u)", ptd->ap);
		_LOG_(":IMP(%01u)", ptd->imp);

		if(!ptd->is_supersection)
			_LOG_(":Domain(%01u)", ptd->domain);

		_LOG_(":XN(%01u)", ptd->xn);
		_LOG_(":%c", ptd->c ? 'C' : 'c');
		_LOG_(":%c", ptd->b ? 'B' : 'b');

		LOG_END();
	}

	const uint32_t ppa = ptd->base | mlBFEXT(va, sba_lsb, 0);
	if(p2ppa)
		*p2ppa = ppa;

	return(1);
}

static inline int _soc_mmu_l1ptd_0(soc_mmu_p mmu, soc_mmu_ptd_p ptd, uint32_t va, uint32_t* p2ppa)
{
	const csx_p csx = mmu->csx;

	const unsigned ttbcr_x = TTBCR & 7;
	const uint32_t ttbr0_ppa = mlBFTST(TTBR0, 31, 14 - ttbcr_x);
	const uint32_t ttbr0_ti = mlBFMOV(va, 31 - ttbcr_x, 20, 2);
	const uint32_t l1ptd_ppa = ttbr0_ppa | ttbr0_ti;

	const uint32_t l1ptd = csx_mem_access_read(csx, l1ptd_ppa, sizeof(uint32_t), 0);

	if(mmu->debug) {
		LOG("TTBR0 = 0x%08x, ttbr0_ppa = 0x%08x, ttbr0_ti = 0x%08x, l1ptd_ppa = 0x%08x, l1ptd = 0x%08x",
			TTBR0, ttbr0_ppa, ttbr0_ti, l1ptd_ppa, l1ptd);
	}

	ptd->raw = l1ptd;
	ptd->type = l1ptd & 3;

	switch(ptd->type) {
		case 2:
			return(_soc_mmu_l1ptd_02(mmu, ptd, va, p2ppa));
			break;
	}

	return(0);
}

static int _soc_mmu_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	soc_mmu_p mmu = param;
	csx_p csx = mmu->csx;

	TTBCR = 0;
	TTBR0 = ~0U;
	CP15_reg1_set(m);

	callback_qlist_process(&mmu->atreset.list);

	return(0);
}

/* **** */

void csx_mmu_dump_ttbr0(csx_p csx)
{
	if(!CP15_reg1_Mbit)
		return;
	if(~0U == TTBR0)
		return;

	const soc_mmu_p mmu = csx->mmu;
	const unsigned savedDebug = mmu->debug;
	mmu->debug = 1;

	const unsigned ttbcr_x = TTBCR & 7;
	const uint32_t last_ti = mlBFEXT(~0, 31 - ttbcr_x, 20);

	for(uint32_t ti = 0; ti <= last_ti; ti++)
	{
		const unsigned va = ti << 20;

		soc_mmu_ptd_t l1ptd;
		unsigned page_size = 0, ppa = 0;

		if(_soc_mmu_l1ptd_0(csx->mmu, &l1ptd, va, &ppa)) {
			switch(l1ptd.type) {
				case 2:
					page_size = mlBF(19, 0);
					break;
			}

			LOG("0x%08x--0x%08x --> 0x%08x--0x%08x", va, va + page_size, ppa, ppa + page_size);
		}
	}

	mmu->debug = savedDebug;
}

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
		LOG(" -- PREFETCH ABORT -- csx = 0x%08" PRIxPTR ", va = 0x%08x, ppa = 0x%08x, size = 0x%08zx",
			(uintptr_t)csx, va, ppa, size);

		csx_exception(csx, _EXCEPTION_PrefetchAbort);
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
		LOG(" -- DATA ABORT -- csx = 0x%08" PRIxPTR ", va = 0x%08x, ppa = 0x%08x, size = 0x%08zx",
			(uintptr_t)csx, va, ppa, size);

		csx_exception(csx, _EXCEPTION_DataAbort);
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
		LOG(" -- DATA ABORT -- csx = 0x%08" PRIxPTR ", va = 0x%08x, ppa = 0x%08x, size = 0x%08zx, data = 0x%08x",
			(uintptr_t)csx, va, ppa, size, data);

		csx_exception(csx, _EXCEPTION_DataAbort);
	}

	if(tlb && dst)
		soc_tlb_fill_data_tlbe_write(tlbe, va, dst);
}



soc_mmu_p soc_mmu_alloc(csx_p csx, csx_soc_p soc, soc_mmu_h h2mmu)
{
	ERR_NULL(csx);
	ERR_NULL(soc);
	ERR_NULL(h2mmu);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_mmu_p mmu = HANDLE_CALLOC(h2mmu, 1, sizeof(soc_mmu_t));
	ERR_NULL(mmu);

	mmu->csx = csx;
	mmu->debug = 0;
	mmu->soc = soc;

	/* **** */

	callback_qlist_init(&mmu->atexit.list, LIST_LIFO);
	callback_qlist_init(&mmu->atreset.list, LIST_FIFO);

	/* **** */

	csx_soc_callback_atexit(soc, &mmu->atexit.elem, _soc_mmu_atexit, h2mmu);
	csx_soc_callback_atreset(soc, &mmu->atreset.elem, _soc_mmu_atreset, mmu);

	/* **** */

	return(mmu);
}

void soc_mmu_init(soc_mmu_p mmu)
{
	ERR_NULL(mmu);

	if(_trace_init) {
		LOG();
	}
}

int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* p2ppa)
{
	static int count = 1;
	const csx_p csx = mmu->csx;

	if(!CP15_reg1_Mbit || (~0U == TTBR0)) {
		*p2ppa = va;
		return(~0U == TTBR0);
	}

	soc_mmu_ptd_t l1ptd;
	if(_soc_mmu_l1ptd_0(mmu, &l1ptd, va, p2ppa))
		return(1);

	count--;
	if(0 >= count)
		LOG_ACTION(exit(-1));

	return(0);
}
