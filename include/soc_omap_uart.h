#pragma once

/* **** */

typedef struct soc_omap_uart_t** soc_omap_uart_h;
typedef struct soc_omap_uart_t* soc_omap_uart_p;

/* **** */

#include "csx.h"

/* **** */

soc_omap_uart_p soc_omap_uart_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_uart_h h2uart);
void soc_omap_uart_init(soc_omap_uart_p uart);
