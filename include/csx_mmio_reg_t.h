#pragma once

/* **** forward type definitions */

typedef struct csx_mmio_reg_t* csx_mmio_reg_p;
typedef struct csx_mmio_reg_trace_t* csx_mmio_reg_trace_p;
typedef struct csx_mmio_regbit_t* csx_mmio_regbit_p;

/* **** csx includes */

#include "csx_mmio.h"
#include "csx_data.h"
#include "csx.h"

/* **** local includes */

#include "bitfield.h"

/* **** system includes */

#include <stdint.h>

/* **** */

#define CSX_MMIO_DATAREG_GET(_name, _type) \
	static inline _type _name(void* pat, uint32_t* value, uint8_t size) { \
		size = size ? size : sizeof(_type); \
	\
		if(_check_pedantic_size) assert(size == sizeof(_type)); \
	\
		return(csx_mmio_datareg_x(pat, _ ## _name, value, size)); \
	}

#define CSX_MMIO_DATAREG_SET(_name, _type) \
	static inline _name ## _SET(void* dst, uint32_t* value, size) { \
		size = size ? size : sizeof(_type); \
	\
		if(_check_pedantic_size) assert(size == sizeof(_type)); \
	\
		csx_mmio_datareg_x(dst, _ ## _name, value, size); \
	}

#define CSX_MMIO_REG_T_DECL(_mpa, _type) \
	{ \
		.mpa = _mpa, \
		.size = sizeof(_type), \
	}

#define CSX_MMIO_REG_DECL(_name, _mpa, _type) \
	csx_mmio_reg_t _name = CSX_MMIO_REG_T_DECL(_mpa, _type)

typedef struct csx_mmio_reg_t {
	uint32_t	mpa;
	size_t		size;
}csx_mmio_reg_t;

#define CSX_MMIO_DATAREGBIT_GET(_basereg, _name, _bit) \
	static inline uint8_t _basereg ## _ ## _name(void* src) { \
		uint32_t data = _basereg(src, 0, 0); \
		\
		return(BEXT(data, _bit)); \
	}

#define CSX_MMIO_REGBIT_DECL(_reg, _bit) \
	csx_mmio_regbit_t _reg ## _bit = { \
		.bit = _bit, \
		.reg = _reg, \
	};

typedef struct csx_mmio_regbit_t {
	csx_mmio_reg_t	reg;
	uint8_t			bit;
}csx_mmio_regbit_t;

#define CSX_MMIO_REG_TRACE_T_DECL(_name, _base, _offset, _size) \
	{ \
		.name = # _name, \
		.reg = CSX_MMIO_REG_T_DECL(_base + _offset, _type), \
	};

typedef struct csx_mmio_reg_trace_t {
	const char* name;
	csx_mmio_reg_t reg;
}csx_mmio_reg_trace_t;
