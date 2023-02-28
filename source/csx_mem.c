#include "csx_mem.h"

/* **** csx project includes */

#include "csx.h"

/* **** local library includes */

#include "err_test.h"
#include "log.h"
#include "page.h"

/* **** system includes */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

static uint32_t _mmap_unmapped(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	LOG("param = %#0" PRIxPTR", ppa = %#08x, size = %#08zx, write = %#08" PRIXPTR "(%#08x)",
		(uintptr_t)param, ppa, size, (uintptr_t)write, write ? *write : 0);

	return(0);
}

static csx_mem_callback_t _mmap_unmapped_callback = {
	.fn = _mmap_unmapped,
};

/* **** */

static int _csx_mem_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	const csx_mem_h h2mem = param;
	csx_mem_p mem = *h2mem;

	for(uint i = 0; i < mem->l2alloc.count; i++) {
		void** h2l2 = &mem->l2alloc.ptr[i];

		free(*h2l2);
		*h2l2 = 0;
	}

	free(mem);
	*h2mem = mem = 0;

	return(0);
}

csx_mem_callback_p _csx_mem_access(csx_mem_p mem, uint32_t ppa, csx_mem_callback_h h2l2page)
{
	const uint32_t l1l2page = PAGE(ppa);
	const uint32_t l1page = PAGE(l1l2page) & PAGE_MASK;
	const uint32_t l2page = l1l2page & PAGE_MASK;
	
	void** l2 = mem->l1[l1page];
	if(h2l2page)
		*h2l2page = (csx_mem_callback_p)l2;

	if(!l2)
		return(0);

	const csx_mem_callback_p cmcbp = l2[l2page];

	if(!cmcbp) {
		LOG("unmapped -- ppa = %#08x", ppa);
		
		return(&_mmap_unmapped_callback);
	}

	return(cmcbp);
}

static csx_mem_callback_p _csx_mem_mmap_alloc(csx_mem_p mem, uint ppa)
{
	const size_t l2size = sizeof(csx_mem_callback_t) * PAGE_SIZE;
	
	csx_mem_callback_h p2l2 = 0;
	csx_mem_callback_p l2 = _csx_mem_access(mem, ppa, p2l2);
	
	if(!l2) {
		qelem_p qel2 = mem->l2free.head;
		if(qel2) {
			if(_trace_mem_mmap_alloc_free) {
				LOG(">> qel2 = %#08" PRIxPTR ", next = %#08" PRIxPTR,
					(uintptr_t)qel2, (uintptr_t)qel2->next);
			}

			l2 = (csx_mem_callback_p)qel2;
			mem->l2free.head = qel2->next;
		} else {
			LOG("l2 -- alloc");
			
			l2 = malloc(l2size);
			
			uint count = mem->l2alloc.count;
			mem->l2alloc.ptr[count] = l2;
			mem->l2alloc.count++;

			if(_trace_mem_mmap_alloc_malloc) {
				LOG(">> malloc = %#08" PRIxPTR ", count = %#08" PRIxPTR,
					(uintptr_t)l2, (uintptr_t)count);
			}
		}

		if(_trace_mem_mmap_alloc) {
			LOG("l2size = %#08zx, p2l2 = %#08" PRIxPTR ", l2 = %#08" PRIxPTR,
				l2size, (uintptr_t)p2l2, (uintptr_t)l2);
		}

		*p2l2 = l2;
		memset(l2, 0, l2size);
	}

	return(&l2[PAGE_OFFSET(ppa)]);
}

static uint32_t _mem_access_generic(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const csx_mem_callback_p cb = param;

	uint8_t* ppat = cb->data;
	ppat -= cb->base;
	ppat += PAGE_OFFSET(ppa);
	
	if(write)
		csx_data_write(ppat, size, *write);
	else
		return(csx_data_read(ppat, size));
	
	return(0);
}

UNUSED_FN
static uint32_t _mem_access_generic_pedantic(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const csx_mem_callback_p cb = param;

	if(ppa >= cb->base) {
//		if(ppa <= cb->end)
			return(_mem_access_generic(param, ppa, size, write));
	}
	
	LOG("generic access failure -- param = %#08" PRIxPTR ", ppa = %#08x, size = %#08zx, write = %#08" PRIxPTR "(%#08x)",
		(uintptr_t)param, ppa, size, (uintptr_t)write, write ? *write : 0);

	LOG_ACTION(abort());
}

csx_mem_callback_p csx_mem_access(csx_p csx, uint32_t ppa)
{
	return(_csx_mem_access(csx->mem, ppa, 0));
}

int csx_mem_init(csx_p csx, csx_mem_h h2mem)
{
	assert(0 != csx);
	assert(0 != h2mem);
	
	if(_trace_init) {
		LOG();
	}
	
	const csx_mem_p mem = calloc(1, sizeof(csx_mem_t));
	ERR_NULL(mem);

	mem->csx = csx;
	*h2mem = mem;

	csx_callback_atexit(csx, _csx_mem_atexit, h2mem);
	
	/* **** */
	
	queue_init(&mem->l2free);
		
	for(uint32_t i = 0; i < PAGE_SIZE; i++)
		enqueue(&mem->l2free, (qelem_p)&mem->l2heap[i]);

	memset(&mem->l2alloc, 0, sizeof(mem->l2alloc));

	return(0);
}

void csx_mem_mmap(csx_p csx, uint32_t base, uint32_t end, csx_mem_fn fn, void* param)
{
	if(_trace_mem_mmap) {
		LOG("base = %#08x, end = %#08x, fn = %#08" PRIxPTR ", param = %#08" PRIxPTR,
			base, end, (uintptr_t)fn, (uintptr_t)param);
	}

	const csx_mem_p mem = csx->mem;

	uint32_t start = base & PAGE_MASK;
	uint32_t stop = end & PAGE_MASK;

	for(uint32_t ppa = start; ppa <= stop; ppa++) {
		csx_mem_callback_p cb = _csx_mem_mmap_alloc(mem, ppa);

		LOG(">> cb = %#08" PRIxPTR ", ppa = %#08x, fn = %#08" PRIxPTR ", param = %#08" PRIxPTR,
			(uintptr_t)cb, ppa, (uintptr_t)fn, (uintptr_t)param);

		cb->base = base;
//		cb->end = end;
		cb->param = param;
		cb->fn = fn;
	}
}
