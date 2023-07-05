#pragma once

/* **** */

typedef struct soc_omap_lcd_t** soc_omap_lcd_h;
typedef struct soc_omap_lcd_t* soc_omap_lcd_p;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_lcd_p soc_omap_lcd_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_lcd_h h2lcd);
void soc_omap_lcd_init(soc_omap_lcd_p lcd);
