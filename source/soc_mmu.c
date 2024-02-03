#include "soc_mmu.h"

#include "soc_core_disasm.h"
#include "soc_core.h"
#include "soc_tlb.h"

/* **** */

#include "csx_cp15_reg1.h"
#include "csx_data.h"
#include "csx_mem.h"
#include "csx_soc_exception.h"
#include "csx_soc.h"
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
#include <inttypes.h>
#include <string.h>

/* **** */

#undef DEBUG
//#define DEBUG(_x) _x

#ifndef DEBUG
	#define DEBUG(_x)
#endif

/* **** */

typedef struct soc_mmu_t* soc_mmu_p;
typedef struct soc_mmu_t {
	csx_p							csx;
	csx_soc_p						soc;
	soc_tlb_p						tlb;

	uint32_t dacr;

	union {
		uint32_t raw;
		struct {
			uint32_t n:3;
		};
	}ttbcr;
	
	uint32_t						ttbr[2];

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
			LOG_START("Supersection Base Address: 0x%016" PRIx64, ptd->base);
		} else {
			LOG_START("Section Base Address: 0x%08" PRIx64, ptd->base);
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

static uint32_t _soc_mmu_cp15_0_3_0_0_access_dacr(void* param, uint32_t* write)
{
	const soc_mmu_p mmu = param;

	uint32_t data = write ? *write : mmu->dacr;

	if(write) {
		LOG_START("Domain Access Control Register\n\t");
		unsigned i = 15;
		do {
			_LOG_("D%02u(%01u)", i, data >> (i << 1) & 3);
			if(i) {
				_LOG_(", ");
			}
		}while(i--);
		LOG_END();
		
		mmu->dacr = data;
	} else {
		DEBUG(LOG("Domain Access Control Register"));
	}

	return(data);
}

static uint32_t _soc_mmu_cp15_access_ttbcr(void* param, uint32_t* write)
{
	const soc_mmu_p mmu = param;

	const uint32_t data = write ? *write : mmu->ttbcr.n;

	if(write)
		mmu->ttbcr.n = mlBFEXT(data, 2, 0);

	return(data);
	
}

static uint32_t _soc_mmu_cp15_access_ttbr(soc_mmu_p mmu, uint32_t* write, unsigned r)
{
	const uint32_t mask = mlBF(31, 14 - mmu->ttbcr.n) | mlBF(4, 3) | _BV(2) | _BV(1) | _BV(0);
	
	const uint32_t data = write ? *write : mmu->ttbr[r];

	if(write) {
		LOG_START("Translation Table Base %01u\n\t", r);
		_LOG_("mmu->ttbr[0]: 0x%05x", mlBFEXT(data, 31, 14));
		_LOG_(" SBZ: 0x%03x", mlBFEXT(data, 13, 5));
		_LOG_(" RGN: %01u", mlBFEXT(data, 4, 3));
		_LOG_(" IMP: %01u", BEXT(data, 2));
		_LOG_(" %c", BEXT(data, 1) ? 'S' : 's');
		LOG_END(" %c", BEXT(data, 0) ? 'C' : 'c');

		mmu->ttbr[r] = data & mask;
	} else {
		DEBUG(LOG("READ -- Translation Table Base %01u", r));
	}

	return(data);
}

static uint32_t _soc_mmu_cp15_access_ttbr0(void* param, uint32_t* write)
{
	return(_soc_mmu_cp15_access_ttbr(param, write, 0));
}

static uint32_t _soc_mmu_cp15_access_ttbr1(void* param, uint32_t* write)
{
	return(_soc_mmu_cp15_access_ttbr(param, write, 1));
}

static inline int _soc_mmu_l1ptd_0(soc_mmu_p mmu, soc_mmu_ptd_p ptd, uint32_t va, uint32_t* p2ppa)
{
	const csx_p csx = mmu->csx;

	const uint32_t ttbr_ppa = mlBFTST(mmu->ttbr[0], 31, 14 - mmu->ttbcr.n);
	const uint32_t ttbr_ti = mlBFMOV(va, 31 - mmu->ttbcr.n, 20, 2);
	const uint32_t l1ptd_ppa = ttbr_ppa | ttbr_ti;

	const uint32_t l1ptd = csx_mem_access_read(csx, l1ptd_ppa, sizeof(uint32_t), 0);

	if(mmu->debug) {
		LOG("mmu->ttbr0 = 0x%08x, mmu->ttbr0_ppa = 0x%08x, mmu->ttbr0_ti = 0x%08x, l1ptd_ppa = 0x%08x, l1ptd = 0x%08x",
			mmu->ttbr[0], ttbr_ppa, ttbr_ti, l1ptd_ppa, l1ptd);
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

	mmu->ttbcr.raw = 0;
	mmu->ttbr[0] = ~0U;
	mmu->ttbr[1] = ~0U;
	CP15_reg1_clear(m);

	callback_qlist_process(&mmu->atreset.list);

	return(0);
}

/* **** */

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

void soc_mmu_dump_ttbr0(soc_mmu_p mmu)
{
	const csx_p csx = mmu->csx;
	
	if(!CP15_reg1_bit(m))
		return;
	if(~0U == mmu->ttbr[0])
		return;

	const unsigned savedDebug = mmu->debug;
	mmu->debug = 1;

	const uint32_t last_ti = mlBFEXT(~0, 31 - mmu->ttbcr.n, 20);

	for(uint32_t ti = 0; ti <= last_ti; ti++)
	{
		const unsigned va = ti << 20;

		soc_mmu_ptd_t l1ptd;
		unsigned page_size = 0, ppa = 0;

		if(_soc_mmu_l1ptd_0(mmu, &l1ptd, va, &ppa)) {
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

uint32_t soc_mmu_ifetch(soc_mmu_p mmu, uint32_t va, size_t size)
{
	const csx_p csx = mmu->csx;
	uint32_t ppa = va;
	csx_mem_callback_p src = 0;
	int tlb = 0;
	soc_tlbe_p tlbe = 0;

	if(CP15_reg1_bit(m)) {
		src = soc_tlb_ifetch(mmu->tlb, va, &tlbe);

		if(src)
			return(csx_mem_callback_read(src, va, size));

		tlb = soc_mmu_vpa_to_ppa(mmu, va, &ppa);
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

void soc_mmu_init(soc_mmu_p mmu)
{
	ERR_NULL(mmu);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	mmu->tlb = mmu->soc->tlb;

	/* **** */

	csx_coprocessor_p cp = mmu->csx->cp;

	csx_coprocessor_register_access(cp, cp15(0, 2, 0, 0),
		_soc_mmu_cp15_access_ttbr0, mmu);
	csx_coprocessor_register_access(cp, cp15(0, 2, 0, 1),
		_soc_mmu_cp15_access_ttbr1, mmu);
	csx_coprocessor_register_access(cp, cp15(0, 2, 0, 2),
		_soc_mmu_cp15_access_ttbcr, mmu);
	csx_coprocessor_register_access(cp, cp15(0, 3, 0, 0),
		_soc_mmu_cp15_0_3_0_0_access_dacr, mmu);
}

uint32_t soc_mmu_read(soc_mmu_p mmu, uint32_t va, size_t size)
{
	const csx_p csx = mmu->csx;
	uint32_t ppa = va;
	csx_mem_callback_p src = 0;
	int tlb = 0;
	soc_tlbe_p tlbe = 0;

	if(CP15_reg1_bit(m)) {
		src = soc_tlb_read(mmu->tlb, va, &tlbe);

		if(src)
			return(csx_mem_callback_read(src, va, size));

		tlb = soc_mmu_vpa_to_ppa(mmu, va, &ppa);
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

int soc_mmu_vpa_to_ppa(soc_mmu_p mmu, uint32_t va, uint32_t* p2ppa)
{
	static int count = 1;
	const csx_p csx = mmu->csx;

	const unsigned invalid_ttbr0 = (~0U == mmu->ttbr[0]);
	if(!CP15_reg1_bit(m) || invalid_ttbr0) {
		*p2ppa = va;
		return(CP15_reg1_bit(m) && invalid_ttbr0);
	}

	soc_mmu_ptd_t l1ptd;
	if(_soc_mmu_l1ptd_0(mmu, &l1ptd, va, p2ppa))
		return(1);

	count--;
	if(0 >= count)
		LOG_ACTION(exit(-1));

	return(0);
}

void soc_mmu_write(soc_mmu_p mmu, uint32_t va, size_t size, uint32_t data)
{
	const csx_p csx = mmu->csx;
	uint32_t ppa = va;
	csx_mem_callback_p dst = 0;
	int tlb = 0;
	soc_tlbe_p tlbe = 0;

	if(CP15_reg1_bit(m)) {
		dst = soc_tlb_write(mmu->tlb, va, &tlbe);

		if(dst)
			return(csx_mem_callback_write(dst, va, size, &data));

		tlb = soc_mmu_vpa_to_ppa(mmu, va, &ppa);
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
