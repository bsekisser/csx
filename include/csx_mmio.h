#pragma once

/* **** forward defines / typedefs */

typedef struct csx_mmio_t** csx_mmio_h;
typedef struct csx_mmio_t* csx_mmio_p;

typedef struct csx_mmio_callback_t* csx_mmio_callback_p;

typedef struct csx_mmio_regtrace_t* csx_mmio_regtrace_p;
typedef struct csx_mmio_regbit_t* csx_mmio_regbit_p;
typedef struct csx_mmio_reg_t* csx_mmio_reg_p;

#define CSX_CALLBACK_COUNT (CSX_MMIO_SIZE >> 1)

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

typedef uint32_t (*csx_mmio_read_fn)(void* param, void* data, uint32_t addr, uint8_t size);
typedef void (*csx_mmio_write_fn)(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size);

typedef struct csx_mmio_reg_t {
	uint32_t mpa;
	uint8_t size;
}csx_mmio_reg_t;

typedef struct csx_mmio_regtrace_t {
	const char* name;
	csx_mmio_reg_t reg;
}csx_mmio_regtrace_t;

typedef struct csx_mmio_regbit_t {
	csx_mmio_reg_t reg;
	uint8_t bit;
}csx_mmio_regbit_t;

typedef struct csx_mmio_callback_t {
	void* param;
	union {
		csx_mmio_read_fn rfn;
		csx_mmio_write_fn wfn;
	};
}csx_mmio_callback_t;

typedef struct csx_mmio_t {
	csx_p csx;
	uint8_t data[CSX_MMIO_SIZE];

	csx_mmio_callback_t read[CSX_CALLBACK_COUNT];
	csx_mmio_callback_t write[CSX_CALLBACK_COUNT];
}csx_mmio_t;

/* **** function prototypes */

void* csx_mmio_data_offset(csx_p csx, uint32_t mpa);

int csx_mmio_init(csx_p csx, csx_mmio_h mmio, void** mmio_data);

uint32_t csx_mmio_read(csx_p csx, uint32_t vaddr, uint8_t size);
uint32_t csx_mmio_write(csx_p csx, uint32_t vaddr, uint32_t data, uint8_t size);

void csx_register_callback_read(csx_p csx, csx_mmio_read_fn fn, uint32_t mpa, void* param);
void csx_register_callback_write(csx_p csx, csx_mmio_write_fn fn, uint32_t mpa, void* param);

/* **** */

static inline uint32_t csx_mmio_reg_read(csx_p csx, csx_mmio_reg_p cmrt)
{
	void* src = csx_mmio_data_offset(csx, cmrt->mpa);

	return(csx_data_read(src, cmrt->size));
}

static inline void csx_mmio_reg_write(csx_p csx, csx_mmio_reg_p cmrt, uint32_t data)
{
	void* dst = csx_mmio_data_offset(csx, cmrt->mpa);

	csx_data_write(dst, data, cmrt->size);
}

static inline void csx_mmio_regbit_bmas(csx_p csx, csx_mmio_regbit_p cmrbt, uint set)
{
	csx_mmio_reg_p reg = &cmrbt->reg;

	void* pat = csx_mmio_data_offset(csx, reg->mpa);

	uint32_t data = csx_data_read(pat, reg->size);

	BMAS(data, cmrbt->bit, set);

	csx_data_write(pat, data, reg->size);
}

static inline void csx_mmio_regbit_clear(csx_p csx, csx_mmio_regbit_p cmrbt)
{
	csx_mmio_regbit_bmas(csx, cmrbt, 0);
}

static inline uint csx_mmio_regbit_read(csx_p csx, csx_mmio_regbit_p cmrbt)
{
	csx_mmio_reg_p reg = &cmrbt->reg;

	void* src = csx_mmio_data_offset(csx, reg->mpa);

	return(BEXT(csx_data_read(src, reg->size), cmrbt->bit));
}

static inline void csx_mmio_regbit_set(csx_p csx, csx_mmio_regbit_p cmrbt)
{
	csx_mmio_regbit_bmas(csx, cmrbt, 1);
}
