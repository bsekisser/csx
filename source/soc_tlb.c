#include "soc_tlb.h"

/* **** */

#include "csx_statistics.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"
#include "page.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define iTLB_BITS 8
#define dTLB_BITS 8

/*
 * xxxx xxxx | xxxx hhhh | hhhh oooo | oooo oooo	-- 256 entries
 * xxxx xxxx | hhhh hhhh | hhhh oooo | oooo oooo	-- 1024 entries
 * xxxx hhhh | hhhh hhhh | hhhh oooo | oooo oooo	-- 64k entries
 */

typedef struct soc_tlbe_t {
	csx_mem_callback_p				cb;
	void*							src;
	void*							dst;
	uint32_t						vp:20;
	uint32_t						u_rwx:3;
	uint32_t						rwx:3;
	uint32_t						i:1;
}soc_tlbe_t;

typedef struct soc_tlb_t {
	soc_tlbe_t						itlb[_BV(iTLB_BITS)];
	soc_tlbe_t						dtlb[_BV(dTLB_BITS)];

	csx_p							csx;
	csx_soc_p						soc;
}soc_tlb_t;

/* **** */

enum {
	rwX = 1,
	rWx = 2,
	Rwx = 4,
	RWX = 7,

	RWx = Rwx | rWx,
	RwX = Rwx | rwX,
};

/* **** */

static int _soc_tlb_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	handle_free(param);
	return(0);
}

static int _soc_tlb_atreset(void* param)
{
	soc_tlb_p tlb = param;
	
	soc_tlb_invalidate_all(tlb);
	
	return(0);
}

static soc_tlbe_p _tlb_entry(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint32_t va,
	soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlbe_table = 0x%08" PRIxPTR ", tlb_bits = %02u, va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlbe_table, tlb_bits, va, (uintptr_t)h2tlbe);

	const uint vp = PAGE(va);
	const uint vp_tlbe = vp & _BM(tlb_bits);

	if(0) LOG("vp = 0x%08x, vp_tlbe = 0x%08x", vp, vp_tlbe);

	const soc_tlbe_p tlbe = &tlbe_table[vp_tlbe];

	if(h2tlbe)
		*h2tlbe = tlbe;

	if(0) LOG("tlbe = 0x%08" PRIxPTR, (uintptr_t)tlbe);

	if(!tlbe->i || (vp != tlbe->vp)) {
		if(0) LOG("vp = 0x%08x, vp_tlbe = 0x%08x, tlbe = 0x%08" PRIxPTR ", i = %01u, tlbe->vp = 0x%08x",
			vp, vp_tlbe, (uintptr_t)tlbe, tlbe->i, tlbe->vp);
		return(0);
	}

	return(tlbe);
}

static void _tlb_fill_tlbe(soc_tlbe_p tlbe, uint32_t va) {
	if(!tlbe->i) {
		tlbe->cb = 0;
		tlbe->src = 0;
		tlbe->dst = 0;
		
#if 0
		tlbe->u_rwx = 0;
		tlbe->rwx = 0;
#endif
	}

	tlbe->i = 1;
	tlbe->vp = PAGE(va);
}

static void _tlb_fill_tlbe_read(soc_tlbe_p tlbe, uint32_t va, void** src)
{
	if(0) LOG("tlbe = 0x%08" PRIxPTR ", va = 0x%08x, data = 0x%08" PRIxPTR,
		(uintptr_t)tlbe, va, (uintptr_t)src);

	_tlb_fill_tlbe(tlbe, va);

	tlbe->src = src;

#if 0
	tlbe->u_rwx |= Rwx;
	tlbe->rwx |= Rwx;
#endif
}

static void _tlb_fill_tlbe_read_ma(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	if(0) LOG("tlbe = 0x%08" PRIxPTR ", va = 0x%08x, cb = 0x%08" PRIxPTR,
		(uintptr_t)tlbe, va, (uintptr_t)cb);

	_tlb_fill_tlbe(tlbe, va);

	tlbe->cb = cb;

	tlbe->u_rwx |= Rwx;
	tlbe->rwx |= Rwx;
}

static void _tlb_fill_tlbe_write(soc_tlbe_p tlbe, uint32_t va, void** dst)
{
	if(0) LOG("tlbe = 0x%08" PRIxPTR ", va = 0x%08x, data = 0x%08" PRIxPTR,
		(uintptr_t)tlbe, va, (uintptr_t)dst);

	_tlb_fill_tlbe(tlbe, va);

	tlbe->dst = dst;

#if 0
	tlbe->u_rwx |= rWx;
	tlbe->rwx |= rWx;
#endif
}

static void _tlb_fill_tlbe_write_ma(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	if(0) LOG("tlbe = 0x%08" PRIxPTR ", va = 0x%08x, cb = 0x%08" PRIxPTR,
		(uintptr_t)tlbe, va, (uintptr_t)cb);

	_tlb_fill_tlbe(tlbe, va);

	tlbe->cb = cb;

	tlbe->u_rwx |= rWx;
	tlbe->rwx |= rWx;
}

static void _tlb_invalidate_all(soc_tlbe_p tlbe_table, uint tlb_bits)
{
	for(uint i = 0; i < _BV(tlb_bits); i++)
		memset(&tlbe_table[i], 0, sizeof(soc_tlbe_t));
//		tlbe_table[i].i = 0;
}

static void* _tlb_read(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint va,
	soc_tlbe_h h2tlbe)
{
	soc_tlbe_p tlbe = _tlb_entry(tlbe_table, tlb_bits, va, h2tlbe);

	if(!tlbe)
		return(0);
#if 0
	if(!(tlbe->rwx & Rwx))
		return(0);
#endif

	return(tlbe->src);
}

static csx_mem_callback_p _tlb_read_ma(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint va,
	soc_tlbe_h h2tlbe)
{
	soc_tlbe_p tlbe = _tlb_entry(tlbe_table, tlb_bits, va, h2tlbe);

	if(!tlbe)
		return(0);

	if(!(tlbe->rwx & Rwx))
		return(0);

	return(tlbe->cb);
}

static void* _tlb_write(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint va,
	soc_tlbe_h h2tlbe)
{
	soc_tlbe_p tlbe = _tlb_entry(tlbe_table, tlb_bits, va, h2tlbe);

	if(!tlbe)
		return(0);

#if 0
	if(!(tlbe->rwx & rWx))
		return(0);
#endif

	return(tlbe->dst);
}

static void* _tlb_write_ma(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint va,
	soc_tlbe_h h2tlbe)
{
	soc_tlbe_p tlbe = _tlb_entry(tlbe_table, tlb_bits, va, h2tlbe);

	if(!tlbe)
		return(0);

	if(!(tlbe->rwx & rWx))
		return(0);

	return(tlbe->cb);
}

#if 0
static void set_tlbe_urwx_rwx(soc_tlbe_p t, int u_rwx, int rwx)
{
	t->u_rwx = u_rwx;
	t->rwx = rwx;
}
#endif

/* **** */

void soc_tlb_fill_data_tlbe_read(soc_tlbe_p tlbe, uint32_t va, void** src)
{
	_tlb_fill_tlbe_read(tlbe, va, src);
}	

void soc_tlb_fill_data_tlbe_read_ma(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	_tlb_fill_tlbe_read_ma(tlbe, va, cb);
}	

void soc_tlb_fill_data_tlbe_write(soc_tlbe_p tlbe, uint32_t va, void** dst)
{
	_tlb_fill_tlbe_write(tlbe, va, dst);
}	

void soc_tlb_fill_data_tlbe_write_ma(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	_tlb_fill_tlbe_write_ma(tlbe, va, cb);
}	

void soc_tlb_fill_instruction_tlbe(soc_tlbe_p tlbe, uint32_t va, void** src)
{
	_tlb_fill_tlbe_read(tlbe, va, src);

#if 0
	t->u_rwx |= rwX;
	t->rwx |= rwX;
#endif
}

void soc_tlb_fill_instruction_tlbe_ma(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	_tlb_fill_tlbe_read_ma(tlbe, va, cb);

	tlbe->u_rwx |= rwX;
	tlbe->rwx |= rwX;
}

void* soc_tlb_ifetch(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	soc_tlbe_p tlbe = 0;
	void* src = _tlb_read(tlb->itlb, iTLB_BITS, va, &tlbe);

	if(h2tlbe)
		*h2tlbe = tlbe;

	CSX_COUNTER_HIT_IF(soc_tlb.ifetch, 0 != src);

	if(!tlbe)
		return(0);
	
#if 0
	if(!(tlbe->rwx & RwX))
		return(0);
#else
	return(src);
#endif
}

csx_mem_callback_p soc_tlb_ifetch_ma(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	csx_mem_callback_p cb = _tlb_read_ma(tlb->itlb, iTLB_BITS, va, h2tlbe);

	soc_tlbe_p tlbe = *h2tlbe;

	if(!(tlbe->rwx & RwX))
		return(0);

	return(cb);
}

int soc_tlb_init(csx_p csx, soc_tlb_h h2tlb)
{
	assert(0 != csx);
	assert(0 != h2tlb);

	if(_trace_init) {
		LOG();
	}

	soc_tlb_p tlb = HANDLE_CALLOC(h2tlb, 1, sizeof(soc_tlb_t));
	ERR_NULL(tlb);
	
	/* **** */
	
	csx_soc_p soc = csx->csx_soc;
	
	tlb->csx = csx;
	tlb->soc = soc;
	
	csx_soc_callback_atexit(soc, _soc_tlb_atexit, h2tlb);
	csx_soc_callback_atreset(soc, _soc_tlb_atreset, tlb);

	/* **** */
	
	return(0);
}

void soc_tlb_invalidate_all(soc_tlb_p tlb)
{
	soc_tlb_invalidate_data(tlb);
	soc_tlb_invalidate_instruction(tlb);
}

void soc_tlb_invalidate_data(soc_tlb_p tlb)
{
	_tlb_invalidate_all(tlb->dtlb, dTLB_BITS);
}

void soc_tlb_invalidate_instruction(soc_tlb_p tlb)
{
	_tlb_invalidate_all(tlb->itlb, iTLB_BITS);
}

void* soc_tlb_read(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	void* src = _tlb_read(tlb->dtlb, dTLB_BITS, va, h2tlbe);

	CSX_COUNTER_HIT_IF(soc_tlb.read, 0 != src);

	return(src);
}

csx_mem_callback_p soc_tlb_read_ma(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	return(_tlb_read_ma(tlb->dtlb, dTLB_BITS, va, h2tlbe));
}

void soc_tlb_reset(soc_tlb_p tlb)
{
	_soc_tlb_atreset(tlb);
}

void* soc_tlb_write(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	void* dst = _tlb_write(tlb->dtlb, dTLB_BITS, va, h2tlbe);

	CSX_COUNTER_HIT_IF(soc_tlb.write, 0 != dst);

	return(dst);
}

csx_mem_callback_p soc_tlb_write_ma(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	return(_tlb_write_ma(tlb->dtlb, dTLB_BITS, va, h2tlbe));
}
