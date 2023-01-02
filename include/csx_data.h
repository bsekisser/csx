#pragma once

/* **** */

typedef struct csx_data_bit_t* csx_data_bit_p;

/* **** */

#include "csx.h"

/* **** */

#define SOC_DATA_BIT_DECL(_offset, _name, _bit, _reg_size) \
	static csx_data_bit_t _offset ## _name = { \
		.bit = _bit, \
		.offset = _offset, \
		.size = _reg_size, \
	};

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

uint32_t csx_data_read(void* p2src, uint8_t size);
void csx_data_write(void* p2dst, uint32_t value, uint8_t size);

void csx_data_bit_bmas(void* p2data, csx_data_bit_p sdbp, uint set);
uint csx_data_bit_read(void* p2src, csx_data_bit_p sdbp);
uint32_t csx_data_read(void* p2src, uint8_t size);
void csx_data_write(void* p2dst, uint32_t value, uint8_t size);

/* **** */

static inline void csx_data_bit_clear(void* p2data, csx_data_bit_p sdbp) {
	csx_data_bit_bmas(p2data, sdbp, 0);
}

static inline void csx_data_bit_set(void* p2data, csx_data_bit_p sdbp) {
	csx_data_bit_bmas(p2data, sdbp, 1);
}
