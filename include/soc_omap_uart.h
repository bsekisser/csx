#pragma once

/* **** */

typedef struct soc_omap_uart_t** soc_omap_uart_h;
typedef struct soc_omap_uart_t* soc_omap_uart_p;

/* **** */

#include "csx.h"

/* **** */

int soc_omap_uart_init(csx_p csx, csx_mmio_p mmio, soc_omap_uart_h h2t);
