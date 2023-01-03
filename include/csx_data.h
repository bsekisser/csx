#pragma once

/* **** forward declarations */

typedef struct csx_data_bit_t* csx_data_bit_p;

/* **** system includes */

#include <endian.h>
#include <stdint.h>

/* **** */

#ifndef uint
	typedef unsigned int uint;
#endif

typedef struct csx_data_bit_t {
	uint8_t bit;
	uint8_t offset;
	uint8_t size;
}csx_data_bit_t;

/*
	typedef struct csx_data_bfx_t {
		uint8_t offset;
		uint8_t msb;
		uint8_t lsb;
	}csx_data_bit_t;
*/

void csx_data_bit_bmas(void* p2data, csx_data_bit_p sdbp, uint set);
uint csx_data_bit_read(void* p2src, csx_data_bit_p sdbp);

uint32_t csx_data_read_x(void* p2src, uint8_t size);
void csx_data_write_x(void* p2dst, uint32_t value, uint8_t size);

/* **** */

static inline uint32_t csx_data_read(void* p2src, uint8_t size) {
	switch(size) {
		case 4:
			return(le32toh(*(uint32_t*)p2src));
		case 2:
			return(le16toh(*(uint16_t*)p2src));
		case 1:
			return(*(uint8_t*)p2src);
	}

	return(csx_data_read_x(p2src, size));
}

static inline void csx_data_write(void* p2dst, uint32_t value, uint8_t size) {
	switch(size) {
		case 4:
			*(uint32_t*)p2dst = htole32((uint32_t)value);
			return;
		case 2:
			*(uint16_t*)p2dst = htole16((uint16_t)value);
			return;
		case 1:
			*(uint8_t*)p2dst = (uint8_t)value;
			return;
	}

	csx_data_write_x(p2dst, value, size);
}

static inline void csx_data_bit_clear(void* p2data, csx_data_bit_p sdbp) {
	csx_data_bit_bmas(p2data, sdbp, 0);
}

static inline void csx_data_bit_set(void* p2data, csx_data_bit_p sdbp) {
	csx_data_bit_bmas(p2data, sdbp, 1);
}
