#pragma once

typedef struct csx_mmio_t** csx_mmio_h;
typedef struct csx_mmio_t* csx_mmio_p;

#define CSX_MMIO_BASE 0xfffb0000
#define CSX_MMIO_STOP 0xfffeffff
#define CSX_MMIO_SIZE (CSX_MMIO_STOP - CSX_MMIO_BASE + 1)

typedef uint32_t (*csx_mmio_read_fn)(void* data, uint32_t addr, uint8_t size);
typedef void (*csx_mmio_write_fn)(void* data, uint32_t addr, uint32_t value, uint8_t size);

typedef struct csx_mmio_peripheral_t* csx_mmio_peripheral_p;
typedef struct csx_mmio_peripheral_t {
	uint32_t			base;
	void				(*reset)(void*);

	csx_mmio_read_fn	read;
	csx_mmio_write_fn	write;
}csx_mmio_peripheral_t;

/* **** */

uint32_t csx_mmio_read(csx_mmio_p mmio, uint32_t addr, uint8_t size);
void csx_mmio_write(csx_mmio_p mmio, uint32_t addr, uint32_t value, uint8_t size);
void csx_mmio_reset(csx_mmio_p mmio);

void csx_mmio_peripheral(csx_mmio_p mmio, csx_mmio_peripheral_p p, void* data);
int csx_mmio_init(csx_p csx, csx_mmio_h mmio);
