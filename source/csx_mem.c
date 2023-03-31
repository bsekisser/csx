#include "csx_mem.h"

/* **** csx project includes */

#include "csx_statistics.h"
#include "csx_data.h"
#include "csx.h"

/* **** local library includes */

#include "err_test.h"
#include "handle.h"
#include "log.h"
#include "page.h"

/* **** system includes */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

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

	handle_free(param);

	return(0);
}

static void* _csx_mem_access_l1(csx_mem_p mem, uint32_t ppa, void*** h2l1e)
{
	// ->l1->l2->csx_mem_callback_t
	// l1->l2->csx_mem_callback_t
	// ->l2->csx_mem_callback_t
	
	void** p2l1e = &mem->l1[PAGE_OFFSET(PAGE(PAGE(ppa)))];
	void* p2l2 = *p2l1e;
	
	if(0) LOG("p2l1e = 0x%08" PRIxPTR ", p2l2 = 0x%08" PRIxPTR,
		(uintptr_t)p2l1e, (uintptr_t)p2l2);

	if(h2l1e)
		*h2l1e = (void*)p2l1e;

	return(p2l2);
}

static csx_mem_callback_p _csx_mem_access_l2(csx_mem_p mem, uint32_t ppa, void* p2l2)
{
	// ->l1->l2->csx_mem_callback_t
	// l1->l2->csx_mem_callback_t
	// ->l2->csx_mem_callback_t

	csx_mem_callback_p l2 = p2l2;

	return(&l2[PAGE_OFFSET(PAGE(ppa))]);
	
	UNUSED(mem);
}

static csx_mem_callback_p _csx_mem_access(csx_mem_p mem, uint32_t ppa, void*** h2l1e)
{
	void* p2l2 = _csx_mem_access_l1(mem, ppa, h2l1e);
	
	if(!p2l2)
		return(0);
	
	return(_csx_mem_access_l2(mem, ppa, p2l2));
}

static csx_mem_callback_p _csx_mem_mmap_alloc_free(csx_mem_p mem)
{
	qelem_p qel2 = mem->l2free.head;
	csx_mem_callback_p p2l2 = (csx_mem_callback_p)qel2;

	if(qel2) {
		if(_trace_mem_mmap_alloc_free) {
			LOG(">> qel2 = 0x%08" PRIxPTR ", next = 0x%08" PRIxPTR,
				(uintptr_t)qel2, (uintptr_t)qel2->next);
		}

		mem->l2free.head = qel2->next;
	}
	
	return(p2l2);
}	

static csx_mem_callback_p _csx_mem_mmap_alloc_malloc(csx_mem_p mem, size_t l2size)
{
	const csx_mem_callback_p p2l2 = malloc(l2size);

	uint count = mem->l2alloc.count;
	mem->l2alloc.ptr[count] = p2l2;
	mem->l2alloc.count++;

	if(_trace_mem_mmap_alloc_malloc) {
		LOG(">> malloc = 0x%08" PRIxPTR ", size = 0x%08zx, count = 0x%08x",
			(uintptr_t)p2l2, l2size, count);
	}

	return(p2l2);
}


static csx_mem_callback_p _csx_mem_mmap_alloc(csx_mem_p mem, uint ppa)
{
	uint l1page = PAGE_OFFSET(PAGE(PAGE(ppa)));
	uint l2page = PAGE_OFFSET(PAGE(ppa));
	uint offset = PAGE_OFFSET(ppa);
	
	if(0) LOG("ppa = 0x%08x -- %03x:%03x:%03x", ppa, l1page, l2page, offset);

	const size_t l2size = sizeof(csx_mem_callback_t) * PAGE_SIZE;

	void** p2l1e = 0;
	csx_mem_callback_p p2l2 = _csx_mem_access(mem, ppa, &p2l1e);
		
	if(!p2l2) {
		p2l2 = _csx_mem_mmap_alloc_free(mem);

		if(!p2l2)
			p2l2 = _csx_mem_mmap_alloc_malloc(mem, l2size);

		if(_trace_mem_mmap_alloc) {
			LOG("l2size = 0x%08zx, p2l1e = 0x%08" PRIxPTR ", l2 = 0x%08" PRIxPTR,
				l2size, (uintptr_t)p2l1e, (uintptr_t)p2l2);
		}

		if(!p2l2)
			return(0);

		*p2l1e = p2l2;
		memset(p2l2, 0, l2size);
		
		p2l2 = &p2l2[PAGE_OFFSET(PAGE(ppa))];
	}

	return(p2l2);
}

static uint32_t _mem_access_generic(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const csx_mem_callback_p cb = param;

	uint8_t* ppat = &cb->data[PAGE_OFFSET(ppa)];

	if(0) LOG("param = 0x%08" PRIxPTR ", ppa = 0x%08x, size = 0x%08zx, write = 0x%08" PRIxPTR "(0x%08x)",
		(uintptr_t)param, ppa, size, (uintptr_t)write, write ? *write : 0);
	
	if(write)
		csx_data_write(ppat, size, *write);
	else
		return(csx_data_read(ppat, size));
	
	return(0);
}

UNUSED_FN static uint32_t _mem_access_generic_counted(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(write) {
		CSX_COUNTER_INC(csx_mem_access.generic.write);
	} else {
		CSX_COUNTER_INC(csx_mem_access.generic.read);
	}

	return(_mem_access_generic(param, ppa, size, write));
}

UNUSED_FN static uint32_t _mem_access_generic_profiled(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	volatile const uint64_t dtime = get_dtime();
	volatile const uint32_t data = _mem_access_generic(param, ppa, size, write);
	CSX_PROFILE_STAT_COUNT(csx_mem_access.generic, dtime);
	return(data);
	UNUSED(dtime);
}

UNUSED_FN
static uint32_t _mem_access_generic_pedantic(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const csx_mem_callback_p cb = param;

	if(ppa >= cb->base) {
//		if(ppa <= cb->end)
			return(_mem_access_generic(param, ppa, size, write));
	}
	
	LOG("generic access failure -- param = 0x%08" PRIxPTR ", ppa = 0x%08x, size = 0x%08zx, write = 0x%08" PRIxPTR "(0x%08x)",
		(uintptr_t)param, ppa, size, (uintptr_t)write, write ? *write : 0);

	LOG_ACTION(abort());
}

static uint32_t _mem_access_generic_ro(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const csx_mem_callback_p cb = param;

	uint8_t* ppat = &cb->data[PAGE_OFFSET(ppa)];
	
	if(1) LOG("param = 0x%08" PRIxPTR ", ppa = 0x%08x, size = 0x%08zx, write = 0x%08" PRIxPTR "(0x%08x)",
		(uintptr_t)param, ppa, size, (uintptr_t)write, write ? *write : 0);

	if(write)
;//		csx_data_write(ppat, size, *write);
	else
		return(csx_data_read(ppat, size));
	
	return(0);
}

UNUSED_FN static uint32_t _mem_access_generic_ro_counted(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(write) {
		CSX_COUNTER_INC(csx_mem_access.generic.ro_write);
	} else {
		CSX_COUNTER_INC(csx_mem_access.generic.ro);
	}
	
	return(_mem_access_generic_ro(param, ppa, size, write));
}

UNUSED_FN static uint32_t _mem_access_generic_ro_profiled(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	volatile const uint64_t dtime = get_dtime();
	volatile const uint32_t data = _mem_access_generic_ro(param, ppa, size, write);
	CSX_PROFILE_STAT_COUNT(csx_mem_access.generic_ro, dtime);
	return(data);
	UNUSED(dtime);
}

csx_mem_callback_p csx_mem_access(csx_p csx, uint32_t ppa)
{
	return(_csx_mem_access(csx->mem, ppa, 0));
}

uint32_t csx_mem_access_read(csx_p csx, uint32_t ppa, size_t size, csx_mem_callback_h h2cb)
{
	csx_mem_callback_p cb = _csx_mem_access(csx->mem, ppa, 0);

	if(h2cb)
		*h2cb = cb;
	
	return(csx_mem_callback_read(cb, ppa, size));
}

csx_mem_callback_p csx_mem_access_write(csx_p csx, uint32_t ppa, size_t size, uint32_t* write)
{
	csx_mem_callback_p cb = _csx_mem_access(csx->mem, ppa, 0);

	csx_mem_callback_write(cb, ppa, size, write);
	
	return(cb);
}

int csx_mem_init(csx_p csx, csx_mem_h h2mem)
{
	assert(0 != csx);
	assert(0 != h2mem);
	
	if(_trace_init) {
		LOG();
	}

	const csx_mem_p mem = HANDLE_CALLOC(h2mem, 1, sizeof(csx_mem_t));
	ERR_NULL(mem);

	mem->csx = csx;

	csx_callback_atexit(csx, _csx_mem_atexit, h2mem);
	
	/* **** */
	
	const uint ppa = 0x12345678;
	const uint l1page = PAGE_OFFSET(PAGE(PAGE(ppa)));
	const uint l2page = PAGE_OFFSET(PAGE(ppa));
	const uint offset = PAGE_OFFSET(ppa);
	
	if(0) {
		LOG_START("PAGE_SIZE = 0x%08zx", (size_t)PAGE_SIZE);
		_LOG_(", 0x%08x --- %03x:%03x:%03x", ppa, l1page, l2page, offset);
		LOG_END();

		LOG_START("sizeof(csx_mem_callback_t) = 0x%08zx", sizeof(csx_mem_callback_t));
		_LOG_(", l2heap_page_size = 0x%08zx", sizeof(mem->l2heap[0]));
		LOG_END();
	}

	queue_init(&mem->l2free);
		
	for(uint32_t i = 0; i < PAGE_SIZE; i++)
		enqueue(&mem->l2free, (qelem_p)&mem->l2heap[i][0]);

	memset(&mem->l2alloc, 0, sizeof(mem->l2alloc));

	return(0);
}

void csx_mem_mmap(csx_p csx, uint32_t base, uint32_t end, csx_mem_fn fn, void* param)
{
	if(_trace_mem_mmap) {
		LOG("base = 0x%08x, end = 0x%08x, fn = 0x%08" PRIxPTR ", param = 0x%08" PRIxPTR,
			base, end, (uintptr_t)fn, (uintptr_t)param);
	}

	const csx_mem_p mem = csx->mem;

	uint32_t start = base & PAGE_MASK;
	uint32_t stop = end & PAGE_MASK;

	for(uint32_t ppa = start; ppa <= stop; ppa += PAGE_SIZE) {
		csx_mem_callback_p cb = _csx_mem_mmap_alloc(mem, ppa);

		if(_trace_mem_mmap) {
			LOG(">> cb = 0x%08" PRIxPTR ", ppa = 0x%08x, fn = 0x%08" PRIxPTR ", param = 0x%08" PRIxPTR,
				(uintptr_t)cb, ppa, (uintptr_t)fn, (uintptr_t)param);
		}

		cb->base = base;

		if(fn && (((csx_mem_fn)~0U) != fn)) {
			cb->fn = fn;
			cb->param = param;
		} else {
			cb->data = &((uint8_t*)param)[ppa - base];
			cb->param = cb;

			if(((csx_mem_fn)~0U) == fn) {
				if(_profile_csx_mem_access)
					cb->fn = _mem_access_generic_ro_profiled;
				else
					cb->fn = _mem_access_generic_ro;
			} else {
				if(_profile_csx_mem_access)
					cb->fn = _mem_access_generic_profiled;
				else
					cb->fn = _mem_access_generic;
			}
		}
	}
}
