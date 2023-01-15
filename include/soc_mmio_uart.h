#pragma once

/* **** */

typedef struct soc_omap_uart_t** soc_omap_uart_h;
typedef struct soc_omap_uart_t* soc_omap_uart_p;

typedef struct soc_mmio_uart_t** soc_mmio_uart_h;
typedef struct soc_mmio_uart_t* soc_mmio_uart_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_omap_uart_t {
	csx_p					csx;
}soc_omap_uart_t;

typedef struct soc_mmio_uart_t {
	csx_p					csx;
	soc_mmio_p				mmio;
	soc_mmio_peripheral_p	mp[3];

	uint64_t				base[3];
}soc_mmio_uart_t;

int soc_omap_uart_init(csx_p csx, soc_omap_uart_h h2t, int i);
int soc_mmio_uart_init(csx_p csx, soc_mmio_p mmio, soc_mmio_uart_h h2t);
