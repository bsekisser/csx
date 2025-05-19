#pragma once

/* **** */

typedef struct soc_omap_uart_tag** soc_omap_uart_hptr;
typedef soc_omap_uart_hptr const soc_omap_uart_href;

typedef struct soc_omap_uart_tag* soc_omap_uart_ptr;
typedef soc_omap_uart_ptr const soc_omap_uart_ref;

/* **** */

#include "csx.h"

/* **** */

soc_omap_uart_ptr soc_omap_uart_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_uart_href h2uart);
void soc_omap_uart_init(soc_omap_uart_ref uart);
