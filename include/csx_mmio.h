#pragma once

/* **** */

typedef struct csx_mmio_tag** csx_mmio_hptr;
typedef csx_mmio_hptr const csx_mmio_href;

typedef struct csx_mmio_tag* csx_mmio_ptr;
typedef csx_mmio_ptr const csx_mmio_ref;

/* **** */
/* **** csx level includes */

#include "csx.h"

/* **** */

#include "libarmvm/include/armvm_mem.h"

/* **** local library level includes */

#include "libbse/include/callback_qlist.h"

/* **** system level includes */
/* **** */

typedef struct csx_mmio_access_list_tag* csx_mmio_access_list_ptr;
typedef csx_mmio_access_list_ptr const csx_mmio_access_list_ref;

typedef struct csx_mmio_access_list_tag {
	armvm_mem_fn fn;
	const char* name;

	uint32_t ppa;
	uint32_t reset_value;
}csx_mmio_access_list_t;

csx_mmio_ptr csx_mmio_alloc(csx_ref csx, csx_mmio_href h2mmio);
void csx_mmio_access_list_reset(csx_mmio_ref mmio, csx_mmio_access_list_ref acl, const size_t size, void *const param);
void csx_mmio_callback_atexit(csx_mmio_ref mmio, callback_qlist_elem_p const cble, callback_fn const fn, void *const param);
void csx_mmio_callback_atreset(csx_mmio_ref mmio, callback_qlist_elem_p const cble, callback_fn const fn, void *const param);
void csx_mmio_init(csx_mmio_ref mmio);
void csx_mmio_register_access(csx_mmio_ref mmio, const uint32_t ppa, armvm_mem_fn const fn, void *const param);
void csx_mmio_register_access_list(csx_mmio_ref mmio, const uint32_t ppa_base, csx_mmio_access_list_ref acl, void *const param);
void csx_mmio_trace_mem_access(csx_ref csx, const uint32_t ppa, const size_t size, uint32_t *const write, const uint32_t read);

/* **** */

typedef struct csx_mmio_trace_tag* csx_mmio_trace_ptr;
typedef csx_mmio_trace_ptr const csx_mmio_trace_ref;

typedef struct csx_mmio_trace_tag {
	const char* function;
	int line;
}csx_mmio_trace_t;

#define CSX_MMIO_TRACE_SETUP() \
	csx_mmio_trace_t __trace = { \
		.function = __func__, \
		.line = __LINE, \
	}

#define CSX_MMIO_TRACE_READ(_csx, _ppa, _size, _data) \
	{ \
		LOG(" cycle = 0x%016" PRIx64 ", %02zu:[0x%08x] >> 0x%08x", \
			CYCLE, _size, _ppa, _data); \
	}

#define CSX_MMIO_TRACE_MEM_ACCESS(_csx, _ppa, _size, _write, _read) \
	{ \
		typeof(_write) __write = _write; \
		\
		if(__write) { \
			CSX_MMIO_TRACE_WRITE(_csx, _ppa, _size, *__write); \
		} else { \
			CSX_MMIO_TRACE_READ(_csx, _ppa, _size, _read); \
		} \
	}

#define CSX_MMIO_TRACE_WRITE(_csx, _ppa, _size, _data) \
	{ \
		LOG("cycle = 0x%016" PRIx64 ", %02zu:[0x%08x] << 0x%08x", \
			CYCLE, _size, _ppa, _data); \
	}

#define MMIO_HILO(_hi, _lo) \
	((_lo) | (((uint32_t)(_hi)) << 16))

#define MMIO_ENUM(_ahi, _alo, _dhi, _dlo, _name, ...) \
	_name = MMIO_HILO(_ahi, _alo),

#define __MMIO_TRACE(_ahilo, _dhilo, _name) \
	.ppa = _ahilo, \
	.reset_value = _dhilo, \
	.name = #_name,

#define __MMIO_TRACE_FN(_ahilo, _dhilo, _name, _fn) \
	.fn = _fn, \
	__MMIO_TRACE(_ahilo, _dhilo, _name)

#define _MMIO_TRACE(_ahi, _alo, _dhi, _dlo, _name) \
	__MMIO_TRACE(MMIO_HILO(_ahi, _alo), MMIO_HILO(_dhi, _dlo), _name)

#define _MMIO_TRACE_FN(_ahi, _alo, _dhi, _dlo, _name, _fn) \
	__MMIO_TRACE_FN(MMIO_HILO(_ahi, _alo), MMIO_HILO(_dhi, _dlo), _name, _fn)


#define MMIO_TRACE(_ahi, _alo, _dhi, _dlo, _name) \
	{ _MMIO_TRACE(_ahi, _alo, _dhi, _dlo, _name) },

#define MMIO_TRACE_FN(_ahi, _alo, _dhi, _dlo, _name, _fn) \
	{ _MMIO_TRACE_FN(_ahi, _alo, _dhi, _dlo, _name, _fn) },
