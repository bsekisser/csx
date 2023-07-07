#include "soc_tlb.h"

/* **** */

#include "csx_coprocessor.h"
#include "csx_statistics.h"
#include "csx.h"

/* **** */

#include "bitfield.h"
#include "callback_qlist.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"
#include "page.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#undef DEBUG
//#define DEBUG(_x) _x

#ifndef DEBUG
	#define DEBUG(_x)
#endif

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

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
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
		LOG(">>");
	}

	handle_free(param);
	
	if(_trace_atexit_pedantic) {
		LOG("<<");
	}
	
	return(0);
}

static int _soc_tlb_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	soc_tlb_p tlb = param;

	soc_tlb_invalidate_all(tlb);

	return(0);
}

static soc_tlbe_p _tlb_entry(soc_tlbe_p tlbe_table,
	unsigned tlb_bits,
	uint32_t va,
	soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlbe_table = 0x%08" PRIxPTR ", tlb_bits = %02u, va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlbe_table, tlb_bits, va, (uintptr_t)h2tlbe);

	const unsigned vp = PAGE(va);
	const unsigned vp_tlbe = vp & _BM(tlb_bits);

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

static void _tlb_fill_tlbe_read(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	if(0) LOG("tlbe = 0x%08" PRIxPTR ", va = 0x%08x, cb = 0x%08" PRIxPTR,
		(uintptr_t)tlbe, va, (uintptr_t)cb);

	_tlb_fill_tlbe(tlbe, va);

	tlbe->cb = cb;

	tlbe->u_rwx |= Rwx;
	tlbe->rwx |= Rwx;
}

static void _tlb_fill_tlbe_write(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	if(0) LOG("tlbe = 0x%08" PRIxPTR ", va = 0x%08x, cb = 0x%08" PRIxPTR,
		(uintptr_t)tlbe, va, (uintptr_t)cb);

	_tlb_fill_tlbe(tlbe, va);

	tlbe->cb = cb;

	tlbe->u_rwx |= rWx;
	tlbe->rwx |= rWx;
}

static void _tlb_invalidate_all(soc_tlbe_p tlbe_table, unsigned tlb_bits)
{
	for(unsigned i = 0; i < _BV(tlb_bits); i++)
		memset(&tlbe_table[i], 0, sizeof(soc_tlbe_t));
//		tlbe_table[i].i = 0;
}

static csx_mem_callback_p _tlb_read(soc_tlbe_p tlbe_table,
	unsigned tlb_bits,
	unsigned va,
	soc_tlbe_h h2tlbe)
{
	soc_tlbe_p tlbe = _tlb_entry(tlbe_table, tlb_bits, va, h2tlbe);

	if(!tlbe)
		return(0);

	if(Rwx != (tlbe->rwx & Rwx))
		return(0);

	return(tlbe->cb);
}

static void* _tlb_write(soc_tlbe_p tlbe_table,
	unsigned tlb_bits,
	unsigned va,
	soc_tlbe_h h2tlbe)
{
	soc_tlbe_p tlbe = _tlb_entry(tlbe_table, tlb_bits, va, h2tlbe);

	if(0 == tlbe)
		return(0);

	if(rWx != (tlbe->rwx & rWx))
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

soc_tlb_p soc_tlb_alloc(csx_p csx, csx_soc_p soc, soc_tlb_h h2tlb)
{
	ERR_NULL(csx);
	ERR_NULL(h2tlb);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	soc_tlb_p tlb = HANDLE_CALLOC(h2tlb, 1, sizeof(soc_tlb_t));
	ERR_NULL(tlb);
	
	/* **** */
	
	tlb->csx = csx;
	tlb->soc = soc;
	
	/* **** */
	
	csx_soc_callback_atexit(soc, &tlb->atexit, _soc_tlb_atexit, h2tlb);
	csx_soc_callback_atreset(soc, &tlb->atreset, _soc_tlb_atreset, tlb);

	/* **** */
	
	return(tlb);
}

static uint32_t _soc_tlb_cp15_0_8_5_0_invalidate_instruction(void* param, uint32_t* write)
{
	const uint32_t data = write ? *write : 0;

	if(write) {
		LOG("Invalidate instruction TLB");
		soc_tlb_invalidate_instruction(param);
	} else {
		DEBUG(LOG("XX READ -- Invalidate instruction TLB"));
	}

	return(data);
}

static uint32_t _soc_tlb_cp15_0_8_6_0_invalidate_data(void* param, uint32_t* write)
{
	const uint32_t data = write ? *write : 0;

	if(write) {
		LOG("Invalidate data TLB");
		soc_tlb_invalidate_data(param);
	} else {
		DEBUG(LOG("XX READ -- Invalidate data TLB"));
	}

	return(data);
}

uint32_t _soc_tlb_cp15_0_8_7_0_invalidate_all(void* param, uint32_t* write)
{
	const uint32_t data = write ? *write : 0;

	if(write) {
		LOG("Invalidate TLB");
		soc_tlb_invalidate_all(param);
	} else {
		DEBUG(LOG("XX READ -- Invalidate TLB"));
	}

	return(data);
}

void soc_tlb_fill_data_tlbe_read(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	_tlb_fill_tlbe_read(tlbe, va, cb);
}	

void soc_tlb_fill_data_tlbe_write(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	_tlb_fill_tlbe_write(tlbe, va, cb);
}	

void soc_tlb_fill_instruction_tlbe(soc_tlbe_p tlbe, uint32_t va, csx_mem_callback_p cb)
{
	_tlb_fill_tlbe_read(tlbe, va, cb);

	tlbe->u_rwx |= rwX;
	tlbe->rwx |= rwX;
}

csx_mem_callback_p soc_tlb_ifetch(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	csx_mem_callback_p cb = _tlb_read(tlb->itlb, iTLB_BITS, va, h2tlbe);

	soc_tlbe_p tlbe = *h2tlbe;

	int miss = (0 == cb);
	miss = (RwX != (tlbe->rwx & RwX));

	CSX_COUNTER_HIT_IF(soc.tlb.ifetch, 0 == miss);

	return(miss ? 0 : cb);
}

void soc_tlb_init(soc_tlb_p tlb)
{
	ERR_NULL(tlb);
	
	if(_trace_init) {
		LOG();
	}
	
	/* **** */
	
	csx_coprocessor_p cp = tlb->csx->cp;

	csx_coprocessor_register_access(cp, cp15(0, 8, 5, 0),
		_soc_tlb_cp15_0_8_5_0_invalidate_instruction, tlb);
	csx_coprocessor_register_access(cp, cp15(0, 8, 6, 0),
		_soc_tlb_cp15_0_8_6_0_invalidate_data, tlb);
	csx_coprocessor_register_access(cp, cp15(0, 8, 7, 0),
		_soc_tlb_cp15_0_8_7_0_invalidate_all, tlb);
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

csx_mem_callback_p soc_tlb_read(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	csx_mem_callback_p cb = _tlb_read(tlb->dtlb, dTLB_BITS, va, h2tlbe);
	
	CSX_COUNTER_HIT_IF(soc.tlb.read, 0 != cb);

	return(cb);
}

void soc_tlb_reset(soc_tlb_p tlb)
{
	_soc_tlb_atreset(tlb);
}

csx_mem_callback_p soc_tlb_write(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08" PRIxPTR ", va = 0x%08x, h2tlbe = 0x%08" PRIxPTR,
		(uintptr_t)tlb, va, (uintptr_t)h2tlbe);

	csx_mem_callback_p cb = _tlb_write(tlb->dtlb, dTLB_BITS, va, h2tlbe);
	
	CSX_COUNTER_HIT_IF(soc.tlb.write, 0 != cb);

	return(cb);
}
