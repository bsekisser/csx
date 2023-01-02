#pragma once

/* **** module includes */

typedef struct csx_mmio_callback_t* csx_mmio_callback_p;

typedef struct csx_mmio_t** csx_mmio_h;
typedef struct csx_mmio_t* csx_mmio_p;

/* **** project includes */

#include "soc_omap_5912.h"

#include "csx_mmio_reg.h"
#include "csx.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

#define CSX_CALLBACK_COUNT (SOC_MMIO_SIZE >> 1)
#define CSX_MMIO_TRACE_REG(_x) _x

/* **** */

typedef uint32_t (*csx_mmio_read_fn)(void* param, void* data, uint32_t addr, uint8_t size);
typedef void (*csx_mmio_write_fn)(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size);

typedef struct csx_mmio_callback_t {
		void*				param;
		union {
			csx_mmio_read_fn	rfn;
			csx_mmio_write_fn	wfn;
		};
}csx_mmio_callback_t;

typedef struct csx_mmio_t {
	csx_p					csx;

	uint8_t					data[CSX_MMIO_SIZE];

	csx_mmio_callback_t		read[CSX_CALLBACK_COUNT];
	csx_mmio_callback_t		write[CSX_CALLBACK_COUNT];
	csx_mmio_reg_trace_t	reg[CSX_CALLBACK_COUNT];
}csx_mmio_t;

/* **** */

void* csx_mmio_data(csx_p csx, uint32_t mpa);
void* csx_mmio_data_mpa(csx_p csx, uint32_t mpa);
uint32_t csx_mmio_read(csx_p csx, uint32_t mpa, size_t size);

void csx_mmio_register_read(csx_p csx, uint32_t pa, soc_mmio_read_fn fn, void* param);
void csx_mmio_register_write(csx_p csx, uint32_t pa, soc_mmio_write_fn fn, void* param);
