#pragma once

/* **** */

typedef struct csx_mmio_t** csx_mmio_h;
typedef struct csx_mmio_t* csx_mmio_p;

/* **** */
/* **** csx level includes */

#include "csx.h"

/* **** local library level includes */

#include "callback_qlist.h"

/* **** system level includes */
/* **** */

typedef struct csx_mmio_access_list_t* csx_mmio_access_list_p;
typedef struct csx_mmio_access_list_t {
	csx_mem_fn fn;
	const char* name;

	uint32_t ppa;
	uint32_t reset_value;
}csx_mmio_access_list_t;

csx_mmio_p csx_mmio_alloc(csx_p csx, csx_mmio_h h2mmio);
void csx_mmio_access_list_reset(csx_mmio_p mmio, csx_mmio_access_list_p acl, size_t size, void* param);
void csx_mmio_callback_atexit(csx_mmio_p mmio, callback_qlist_elem_p cble, callback_fn fn, void* param);
void csx_mmio_callback_atreset(csx_mmio_p mmio, callback_qlist_elem_p cble, callback_fn fn, void* param);
void csx_mmio_init(csx_mmio_p mmio);
void csx_mmio_register_access(csx_mmio_p mmio, uint32_t ppa, csx_mem_fn fn, void* param);
void csx_mmio_register_access_list(csx_mmio_p mmio, uint32_t ppa_base, csx_mmio_access_list_p acl, void* param);
void csx_mmio_trace_mem_access(csx_p csx, uint32_t ppa, size_t size, uint32_t* write, uint32_t read);

/* **** */

typedef struct csx_mmio_trace_t* csx_mmio_trace_p;
typedef struct csx_mmio_trace_t {
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
			_csx->cycle, _size, _ppa, _data); \
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
			_csx->cycle, _size, _ppa, _data); \
	}

#define MMIO_HILO(_hi, _lo) \
	((_lo) | ((_hi) << 16))

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
