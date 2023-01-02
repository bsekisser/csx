#pragma once

/* **** */

typedef struct soc_data_bit_t* soc_data_bit_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_data_bit_t {
	uint8_t bit;
	uint8_t offset;
	uint8_t size;
}soc_data_bit_t;

/*
	typedef struct soc_data_bfx_t {
		uint8_t offset;
		uint8_t msb;
		uint8_t lsb;
	}soc_data_bit_t;
*/

void soc_data_bit_bmas(void* p2data, soc_data_bit_p sdbp, uint set);
uint soc_data_bit_read(void* p2src, soc_data_bit_p sdbp);
uint32_t soc_data_read(void* p2src, uint8_t size);
void soc_data_write(void* p2dst, uint32_t value, uint8_t size);

/* **** */

static inline void soc_data_bit_clear(void* p2data, soc_data_bit_p sdbp) {
	soc_data_bit_bmas(p2data, sdbp, 0);
}

static inline void soc_data_bit_set(void* p2data, soc_data_bit_p sdbp) {
	soc_data_bit_bmas(p2data, sdbp, 1);
}
