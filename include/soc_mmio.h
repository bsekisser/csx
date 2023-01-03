#pragma once

/* **** */

typedef struct ea_trace_t* ea_trace_p;

typedef struct soc_mmio_t** soc_mmio_h;
typedef struct soc_mmio_t* soc_mmio_p;

typedef struct soc_mmio_peripheral_t* soc_mmio_peripheral_p;

#define CSX_MMIO_BASE 0xfffb0000
#define CSX_MMIO_STOP 0xfffeffff
#define CSX_MMIO_SIZE (CSX_MMIO_STOP - CSX_MMIO_BASE + 1)

/* **** */

#include "csx.h"

/* **** */

typedef uint32_t (*soc_mmio_read_fn)(void* param, void* data, uint32_t addr, uint8_t size);
typedef void (*soc_mmio_write_fn)(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size);

typedef struct soc_mmio_peripheral_t {
	uint32_t			base;
	ea_trace_p			trace_list;

	void				(*reset)(void*, void*, soc_mmio_peripheral_p);

	soc_mmio_read_fn	read;
	soc_mmio_write_fn	write;
}soc_mmio_peripheral_t;

/* **** */

uint32_t soc_mmio_read(soc_mmio_p mmio, uint32_t addr, uint8_t size);
void soc_mmio_write(soc_mmio_p mmio, uint32_t addr, uint32_t value, uint8_t size);
void soc_mmio_reset(soc_mmio_p mmio);

void soc_mmio_peripheral(soc_mmio_p mmio, soc_mmio_peripheral_p p, void* data);
uint32_t soc_mmio_peripheral_read(uint32_t addr, void* data, ea_trace_p tl);
void soc_mmio_peripheral_reset(soc_mmio_p mmio, soc_mmio_peripheral_p p);
void soc_mmio_peripheral_write(uint32_t addr, uint32_t value, void* data, ea_trace_p tl);

int soc_mmio_init(csx_p csx, soc_mmio_h mmio);
