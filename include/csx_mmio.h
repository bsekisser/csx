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
#include "callback_list.h"

/* **** system includes */

#include <stdint.h>

/* **** */

#define CSX_CALLBACK_COUNT (SOC_MMIO_SIZE >> 1)

typedef uint32_t (*csx_mmio_read_fn)(void* param, void* data, uint32_t mpa, size_t size);
typedef void (*csx_mmio_write_fn)(void* param, void* data, uint32_t mpa, size_t size, uint32_t value);

typedef struct csx_mmio_callback_t {
	const char* name;
	void* param;
	union {
		csx_mmio_read_fn rfn;
		csx_mmio_write_fn wfn;
	};
	uint8_t size;
}csx_mmio_callback_t;

typedef struct csx_mmio_trace_t {
	const char*	name;

	uint32_t	mpa;
	uint32_t	reset_value;

	struct {
		uint8_t	access:2;
		uint8_t	size:4;
	};
}csx_mmio_trace_t;

typedef struct csx_mmio_t {
	csx_p csx;
	uint8_t data[SOC_MMIO_SIZE];

	csx_mmio_callback_t read[CSX_CALLBACK_COUNT];
	csx_mmio_callback_t write[CSX_CALLBACK_COUNT];
	
	uint8_t reset_value[SOC_MMIO_SIZE];
	csx_mmio_trace_p trace_list[0x400];
	uint8_t trace_list_count;

	callback_list_t atexit_list;
	callback_list_t atreset_list;
}csx_mmio_t;

/* **** function prototypes */

void* csx_mmio_data_offset(csx_p csx, uint32_t mpa);

static inline uint32_t csx_mmio_datareg_get(void* pat, uint32_t mpao, size_t size)
{
	return(csx_data_offset_read(pat, mpao, size));
}

static inline void csx_mmio_datareg_set(void* pat, uint32_t mpao, size_t size, uint32_t value)
{
	csx_data_offset_write(pat, mpao, size, value);
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
	size_t size,
	uint32_t value,
	uint8_t action)
{
	int wb = 1;

	uint32_t data = csx_mmio_datareg_get(pat, mpao, size);

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
		csx_mmio_datareg_set(pat, mpao, size, data);

	return(data);
}

__attribute__((unused))
static uint32_t csx_mmio_datareg_x(void* pat, uint32_t mpao, size_t size, uint32_t* value)
{
	if(value) {
		csx_mmio_datareg_set(pat, mpao, size, *value);
		return(*value);
	}

	return(csx_mmio_datareg_get(pat, mpao, size));
}

void csx_mmio_callback_atexit(csx_mmio_p mmio, callback_fn fn, void* param);
void csx_mmio_callback_atreset(csx_mmio_p mmio, callback_fn fn, void* param);

int csx_mmio_has_callback_read(csx_p csx, uint32_t mpa);
int csx_mmio_has_callback_write(csx_p csx, uint32_t mpa);

int csx_mmio_init(csx_p csx, csx_mmio_h h2mmio, void** mmio_data);

uint32_t csx_mmio_read(csx_p csx, uint32_t mpa, size_t size);
void csx_mmio_write(csx_p csx, uint32_t mpa, size_t size, uint32_t data);

int csx_mmio_register_read(csx_p csx, csx_mmio_read_fn fn, uint32_t mpa, void* param);
int csx_mmio_register_trace_list(csx_p csx, csx_mmio_trace_p fn);
int csx_mmio_register_write(csx_p csx, csx_mmio_write_fn fn, uint32_t mpa, void* param);

/* **** */
