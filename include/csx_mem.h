#pragma once

/* **** forward definitions/declarations */

typedef struct csx_mem_t** csx_mem_h;
typedef struct csx_mem_t* csx_mem_p;

typedef struct csx_mem_callback_t** csx_mem_callback_h;
typedef struct csx_mem_callback_t* csx_mem_callback_p;

#include <stddef.h>
#include <stdint.h>

typedef uint32_t (*csx_mem_fn)(void* param, uint32_t ppa, size_t size, uint32_t* write);

/* **** csx project includes */

#include "csx.h"

/* **** local includes */

#include "page.h"
#include "queue.h"

/* **** */

typedef struct csx_mem_callback_t {
	csx_mem_fn fn;

	void* param;
	uint8_t* data;

	uint32_t base;
//	uint32_t end;
}csx_mem_callback_t;

typedef struct csx_mem_t {
	void* l1[PAGE_SIZE];
	csx_mem_callback_t l2heap[PAGE_SIZE][PAGE_SIZE];

	queue_t l2free;

	struct {
		void* ptr[PAGE_SIZE];
		uint32_t count;
		uint32_t limit;
	}l2alloc;

	csx_p csx;
}csx_mem_t;

/* **** */

static inline uint32_t csx_mem_callback_read(csx_mem_callback_p cb, uint32_t ppa, size_t size) {
	if(cb)
		return(cb->fn(cb->param, ppa, size, 0));

	return(0);
}

static inline void csx_mem_callback_write(csx_mem_callback_p cb, uint32_t ppa, size_t size, uint32_t* write) {
	if(cb)
		cb->fn(cb->param, ppa, size, write);
}

csx_mem_callback_p csx_mem_access(csx_p csx, uint32_t ppa);
uint32_t csx_mem_access_read(csx_p csx, uint32_t ppa, size_t size, csx_mem_callback_h h2cb);
csx_mem_callback_p csx_mem_access_write(csx_p csx, uint32_t ppa, size_t size, uint32_t* write);
int csx_mem_init(csx_p csx, csx_mem_h h2mem);
void csx_mem_mmap(csx_p csx, uint32_t base, uint32_t end, csx_mem_fn fn, void* param);
