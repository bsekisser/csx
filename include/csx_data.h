#pragma once

/* **** forward declarations */

typedef struct csx_data_bit_t* csx_data_bit_p;
typedef struct csx_data_target_t* csx_data_target_p;

/* **** local library includes */

#include "libbse/include/bitfield.h"
#include "libbse/include/mem_access_le.h"

/* **** system includes */

#include <endian.h>
#include <stddef.h>
#include <stdint.h>

/* **** */

typedef struct csx_data_bit_t {
	uint8_t bit;
	uint8_t offset;
	size_t size;
}csx_data_bit_t;

typedef struct csx_data_target_t {
	void* base;
	unsigned offset;
	size_t size;
}csx_data_target_t;

/*
	typedef struct csx_data_bfx_t {
		uint8_t offset;
		uint8_t msb;
		uint8_t lsb;
	}csx_data_bit_t;
*/

void csx_data_bit_bmas(void* p2data, csx_data_bit_p sdbp, unsigned set);
unsigned csx_data_bit_read(void* p2src, csx_data_bit_p sdbp);

/* **** */

static inline uint32_t csx_data_read(void* p2src, size_t size) {
	return(mem_access_le(p2src, size, 0));
}

static inline uint32_t csx_data_offset_read(void* p2src, uint32_t offset, size_t size) {
	return(csx_data_read((char*)p2src + offset, size));
}

static inline void csx_data_write(void* p2dst, size_t size, uint32_t value) {
	mem_access_le(p2dst, size, &value);
}

static inline void csx_data_offset_write(void* p2src, uint32_t offset, size_t size, uint32_t value) {
	csx_data_write((char*)p2src + offset, size, value);
}

static inline void csx_data_bit_clear(void* p2data, csx_data_bit_p sdbp) {
	csx_data_bit_bmas(p2data, sdbp, 0);
}

static inline void csx_data_bit_set(void* p2data, csx_data_bit_p sdbp) {
	csx_data_bit_bmas(p2data, sdbp, 1);
}

/* **** */

static inline uint32_t csx_data_mem_access(void* p2sd, size_t size, uint32_t* write) {
	return(mem_access_le(p2sd, size, write));
}

static inline uint32_t csx_data_offset_mem_access(void* p2sd, uint32_t offset, size_t size, uint32_t* write) {
	uint32_t data = write ? *write : 0;

	if(write)
		csx_data_offset_write(p2sd, offset, size, data);
	else
		data = csx_data_offset_read(p2sd, offset, size);

	return(data);
}

static inline uint32_t csx_data_target_mem_access(csx_data_target_p cdt,
	size_t size,
	uint32_t* write)
{
	void* const p2target = cdt->base + cdt->offset;
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
