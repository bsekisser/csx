#pragma once

/* **** forward defines / typedefs */

typedef struct csx_mmio_t** csx_mmio_h;
typedef struct csx_mmio_t* csx_mmio_p;

typedef struct csx_mmio_callback_t* csx_mmio_callback_p;
typedef struct csx_mmio_trace_t* csx_mmio_trace_p;

/* **** soc includes */

#include "soc_mmio.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx.h"

/* **** local includes */

#include "bitfield.h"

/* **** system includes */

#include <stdint.h>

/* **** */

#define CSX_MODULE_COUNT ((SOC_MMIO_SIZE >> 8) & 0x3ff)

typedef struct csx_mmio_callback_t {
	void* param;
	union {
		csx_callback_read_fn rfn;
		csx_callback_write_fn wfn;
	};
}csx_mmio_callback_t;

typedef struct csx_mmio_t {
	csx_p csx;
	uint8_t data[SOC_MMIO_SIZE];

	csx_mmio_callback_t read[CSX_MODULE_COUNT];
	csx_mmio_callback_t write[CSX_MODULE_COUNT];
	csx_callback_reset_fn reset[CSX_MODULE_COUNT];
}csx_mmio_t;

/* **** function prototypes */

void* csx_mmio_data_offset(csx_p csx, uint32_t mpa);

static inline uint32_t csx_mmio_datareg_get(void* pat, uint32_t mpao, size_t size)
{
	void* sdmpao = pat + mpao;

	return(csx_data_read(sdmpao, size));
}

enum {
	_MMIO_AND,
	_MMIO_OR,
	_MMIO_BIC,
	_MMIO_EOR,
	_MMIO_TEQ,
	_MMIO_XOR,
};

static inline uint32_t csx_mmio_datareg_rmw(
	void* pat,
	uint32_t mpao,
	uint32_t value,
	size_t size,
	uint8_t action)
{
	void* sdmpao = pat + mpao;
	int wb = 1;

	uint32_t data = csx_data_read(sdmpao, size);

	switch(action) {
		case _MMIO_AND:
			data &= value;
			break;
		case _MMIO_BIC:
			data &= ~value;
			break;
		case _MMIO_OR:
			data |= value;
			break;
		case _MMIO_TEQ:
			wb = 0;
			__attribute__((fallthrough));
		case _MMIO_EOR:
		case _MMIO_XOR:
			data ^= value;
			break;
	}

	if(wb)
		csx_data_write(sdmpao, data, size);

	return(data);
}


static inline void csx_mmio_datareg_set(void* pat, uint32_t mpao, uint32_t value, size_t size)
{
	void* sdmpao = pat + mpao;

	csx_data_write(sdmpao, value, size);
}

__attribute__((unused))
static uint32_t csx_mmio_datareg_x(void* pat, uint32_t mpao, uint32_t* value, size_t size)
{
	if(value) {
		csx_mmio_datareg_set(pat, mpao, *value, size);
		return(*value);
	}

	return(csx_mmio_datareg_get(pat, mpao, size));
}

csx_callback_read_fn csx_mmio_has_callback_read(csx_p csx, uint32_t mpa);
csx_callback_write_fn csx_mmio_has_callback_write(csx_p csx, uint32_t mpa);

int csx_mmio_init(csx_p csx, csx_mmio_h mmio, void** mmio_data);

void csx_mmio_module_reset(csx_p csx, uint32_t mpa);

uint32_t csx_mmio_read(csx_p csx, uint32_t mpa, uint8_t size);
void csx_mmio_write(csx_p csx, uint32_t mpa, uint32_t data, uint8_t size);

int csx_mmio_register_module_read(csx_p csx, csx_callback_read_fn fn, uint32_t mpa, void* param);
int csx_mmio_register_reset(csx_p csx, csx_callback_reset_fn fn, uint32_t mpa, void* param);
int csx_mmio_register_module_write(csx_p csx, csx_callback_write_fn fn, uint32_t mpa, void* param);

/* **** */

#define CSX_MMIO_TRACE_READ(_csx, _mpa, _size, _data) \
	LOG("cycle = 0x%016" PRIx64 ", %02u:[0x%08x] >> 0x%08x", \
			_csx->cycle, _size, _mpa, _data);

#define CSX_MMIO_TRACE_WRITE(_csx, _mpa, _size, _data) \
	LOG("cycle = 0x%016" PRIx64 ", %02u:[0x%08x] << 0x%08x", \
			_csx->cycle, _size, _mpa, _data);
