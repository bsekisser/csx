#pragma once

/* **** forward declarations */

typedef struct csx_data_bit_tag* csx_data_bit_ptr;
typedef csx_data_bit_ptr const csx_data_bit_ref;

typedef struct csx_data_target_tag* csx_data_target_ptr;
typedef csx_data_target_ptr const csx_data_target_ref;

/* **** local library includes */

#include "libbse/include/bitfield.h"
#include "libbse/include/mem_access_le.h"

/* **** system includes */

#include <endian.h>
#include <stddef.h>
#include <stdint.h>

/* **** */

typedef struct csx_data_bit_tag {
	uint8_t bit;
	uint8_t offset;
	size_t size;
}csx_data_bit_t;

typedef struct csx_data_target_tag {
	void* base;
	unsigned offset;
	size_t size;
}csx_data_target_t;

/*
	typedef struct csx_data_bfx_tag {
		uint8_t offset;
		uint8_t msb;
		uint8_t lsb;
	}csx_data_bit_t;
*/

void csx_data_bit_bmas(void *const p2data, csx_data_bit_ref sdbp, const unsigned set);
unsigned csx_data_bit_read(void *const p2src, csx_data_bit_ref sdbp);

/* **** */

static inline uint32_t csx_data_read(void *const p2src, const size_t size) {
	return(mem_access_le(p2src, size, 0));
}

static inline uint32_t csx_data_offset_read(void *const p2src, const uint32_t offset, const size_t size) {
	return(csx_data_read((char*)p2src + offset, size));
}

static inline void csx_data_write(void *const p2dst, const size_t size, uint32_t value) {
	mem_access_le(p2dst, size, &value);
}

static inline void csx_data_offset_write(void *const p2src, const uint32_t offset, const size_t size, const uint32_t value) {
	csx_data_write((char*)p2src + offset, size, value);
}

static inline void csx_data_bit_clear(void *const p2data, csx_data_bit_ptr sdbp) {
	csx_data_bit_bmas(p2data, sdbp, 0);
}

static inline void csx_data_bit_set(void *const p2data, csx_data_bit_ptr sdbp) {
	csx_data_bit_bmas(p2data, sdbp, 1);
}

/* **** */

static inline uint32_t csx_data_mem_access(void *const p2sd, const size_t size, uint32_t *const write) {
	return(mem_access_le(p2sd, size, write));
}

static inline uint32_t csx_data_offset_mem_access(void *const p2sd, const uint32_t offset, const size_t size, uint32_t *const write) {
	uint32_t data = write ? *write : 0;

	if(write)
		csx_data_offset_write(p2sd, offset, size, data);
	else
		data = csx_data_offset_read(p2sd, offset, size);

	return(data);
}

static inline uint32_t csx_data_target_mem_access(csx_data_target_ref cdt,
	const size_t size,
	const uint32_t *const write)
{
	void *const p2target = cdt->base + cdt->offset;
	const uint32_t data = write ? *write : csx_data_read(p2target, cdt->size);

	if(write) {
		uint32_t data_write = data;

		if(cdt->size > size) {
			const uint32_t target_data = csx_data_read(p2target, cdt->size);
			data_write = pbBFINS(target_data, data, 0, size << 3);
		}

		csx_data_write(p2target, cdt->size, data_write);
	}

	return(data);
}
