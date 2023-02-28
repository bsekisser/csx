#pragma once

/* **** forward definitions/declarations */

typedef struct csx_mem_t** csx_mem_h;
typedef struct csx_mem_t* csx_mem_p;

typedef struct csx_mem_callback_t*** csx_mem_callback_hp;
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
	void* data;

	uint32_t base;
//	uint32_t end;
}csx_mem_callback_t;

typedef struct csx_mem_t {
	void** l1[PAGE_SIZE];
	csx_mem_callback_t l2heap[PAGE_SIZE][PAGE_SIZE];

	queue_t l2free;

	struct {
		void* ptr[PAGE_SIZE];
		uint32_t count;
		uint32_t limit;
	}l2alloc;

	csx_p csx;
}csx_mem_t;

csx_mem_callback_p csx_mem_access(csx_p csx, uint32_t ppa);
int csx_mem_init(csx_p csx, csx_mem_h h2mem);
void csx_mem_mmap(csx_p csx, uint32_t base, uint32_t end, csx_mem_fn fn, void* param);
