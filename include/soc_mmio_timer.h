#pragma once

/* **** */

typedef struct soc_mmio_timer_t** soc_mmio_timer_h;
typedef struct soc_mmio_timer_t* soc_mmio_timer_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_timer_t {
	csx_p			csx;
	soc_mmio_p		mmio;
	
	struct {
		uint64_t		base;
		uint32_t		cntl;
		uint32_t		value;
	}unit[3];
}soc_mmio_timer_t;

int soc_mmio_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_timer_h h2t);
//uint32_t soc_mmio_timer_read(soc_mmio_timer_p t, uint32_t address, uint8_t size);
//void soc_mmio_timer_reset(soc_mmio_timer_p t);
//void soc_mmio_timer_write(soc_mmio_timer_p t, uint32_t address, uint32_t value, uint8_t size);
