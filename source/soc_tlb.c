#include "soc_tlb.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
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
	void*							data;
	uint32_t						vp:20;
	uint32_t						u_rwx:3;
	uint32_t						rwx:3;
	uint32_t						i:1;
}soc_tlbe_t;

typedef struct soc_tlb_t {
	soc_tlbe_t						itlb[_BV(iTLB_BITS)];
	soc_tlbe_t						dtlb[_BV(dTLB_BITS)];

	csx_p							csx;
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

static soc_tlbe_p _tlb_entry(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint32_t va,
	soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlbe_table = 0x%08x, tlb_bits = %02u, va = 0x%08x, h2tlbe = 0x%08x",
		(uint)tlbe_table, tlb_bits, va, (uint)h2tlbe);

	const uint vp = PAGE(va);
	const uint vp_tlbe = vp & _BM(tlb_bits);

	if(0) LOG("vp = 0x%08x, vp_tlbe = 0x%08x", vp, vp_tlbe);

	const soc_tlbe_p tlbe = &tlbe_table[vp_tlbe];

	if(h2tlbe)
		*h2tlbe = tlbe;

	if(0) LOG("tlbe = 0x%08x", (uint)tlbe);

	if(!tlbe->i || (vp != tlbe->vp)) {
		if(0) LOG("vp = 0x%08x, vp_tlbe = 0x%08x, tlbe = 0x%08x, i = %01u, tlbe->vp = 0x%08x",
			vp, vp_tlbe, (uint)tlbe, tlbe->i, tlbe->vp);
		return(0);
	}

	return(tlbe);
}

static void _tlb_fill_tlbe(soc_tlbe_p tlbe, uint32_t va, void** data)
{
	if(0) LOG("tlbe = 0x%08x, va = 0x%08x, data = 0x%08x", (uint)tlbe, va, (uint)data);

	tlbe->data = data;
	tlbe->i = 1;
	tlbe->rwx = RWX;
	tlbe->u_rwx = RWX;
	tlbe->vp = PAGE(va);
}

static soc_tlbe_p _tlb_fill(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint va,
	void** data)
{
	soc_tlbe_p tlbe = 0;
	
	_tlb_entry(tlbe_table, tlb_bits, va, &tlbe);
	_tlb_fill_tlbe(tlbe, va, data);

	return(tlbe);
}

static void* _tlb_read(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint va,
	soc_tlbe_h h2tlbe)
{
	soc_tlbe_p tlbe = _tlb_entry(tlbe_table, tlb_bits, va, h2tlbe);

	if(!tlbe)
		return(0);

	if(!(tlbe->rwx & Rwx))
		return(0);

	return(tlbe->data);
}

static void* _tlb_write(soc_tlbe_p tlbe_table,
	uint tlb_bits,
	uint va,
	soc_tlbe_h h2tlbe)
{
	soc_tlbe_p tlbe = _tlb_entry(tlbe_table, tlb_bits, va, h2tlbe);

	if(!tlbe)
		return(0);

	if(!(tlbe->rwx & rWx))
		return(0);

	return(tlbe->data);
}

static void _tlb_invalidate_all(soc_tlbe_p tlbe_table, uint tlb_bits)
{
	for(int i = 0; i < _BV(tlb_bits); i++)
		memset(&tlbe_table[i], 0, sizeof(void*));
}

static void set_tlbe_urwx_rwx(soc_tlbe_p t, int u_rwx, int rwx)
{
	t->u_rwx = u_rwx;
	t->rwx = rwx;
}

/* **** */

void* soc_tlb_ifetch(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08x, va = 0x%08x, h2tlbe = 0x%08x", (uint)tlb, va, (uint)h2tlbe);

	soc_tlbe_p tlbe = _tlb_entry(tlb->itlb, iTLB_BITS, va, h2tlbe);

	if(!tlbe)
		return(0);

	if(!(tlbe->rwx & RwX))
		return(0);

	return(tlbe->data);
}

int soc_tlb_init(csx_p csx, soc_tlb_h h2tlb)
{
	if(0) LOG("csx = 0x%08x, h2tlb = 0x%08x", (uint)csx, (uint)h2tlb);

	soc_tlb_p tlb = calloc(1, sizeof(soc_tlb_t));
	ERR_NULL(tlb);
	if(!tlb)
		return(-1);
	
	/* **** */
	
	tlb->csx = csx;
	
	/* **** */
	
	*h2tlb = tlb;
	
	return(0);
}

void soc_tlb_fill_data_tlbe(soc_tlbe_p tlbe, uint32_t va, void** data)
{
	_tlb_fill_tlbe(tlbe, va, data);
	set_tlbe_urwx_rwx(tlbe, RWx, RWx);
}	


void soc_tlb_fill_instruction_tlbe(soc_tlbe_p tlbe, uint32_t va, void** data)
{
	_tlb_fill_tlbe(tlbe, va, data);
	set_tlbe_urwx_rwx(tlbe, RwX, RwX);
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
	_tlb_invalidate_all(tlb->itlb, dTLB_BITS);
}

void* soc_tlb_read(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08x, va = 0x%08x, h2tlbe = 0x%08x", (uint)tlb, va, (uint)h2tlbe);

	return(_tlb_read(tlb->dtlb, dTLB_BITS, va, h2tlbe));
}

void soc_tlb_reset(soc_tlb_p tlb)
{
	if(0) LOG("tlb = 0x%08x", (uint)tlb);

	soc_tlb_invalidate_all(tlb);
}

void* soc_tlb_write(soc_tlb_p tlb, uint32_t va, soc_tlbe_h h2tlbe)
{
	if(0) LOG("tlb = 0x%08x, va = 0x%08x, h2tlbe = 0x%08x", (uint)tlb, va, (uint)h2tlbe);

	return(_tlb_write(tlb->dtlb, dTLB_BITS, va, h2tlbe));
}
