#pragma once

/* **** */

typedef struct soc_omap_lcd_tag** soc_omap_lcd_hptr;
typedef soc_omap_lcd_hptr const soc_omap_lcd_href;

typedef struct soc_omap_lcd_tag* soc_omap_lcd_ptr;
typedef soc_omap_lcd_ptr const soc_omap_lcd_ref;

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

soc_omap_lcd_ptr soc_omap_lcd_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_lcd_href h2lcd);
void soc_omap_lcd_init(soc_omap_lcd_ref lcd);
