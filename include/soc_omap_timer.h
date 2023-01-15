#pragma once

/* **** forward declarations */

typedef struct soc_omap_timer_t** soc_omap_timer_h;
typedef struct soc_omap_timer_t* soc_omap_timer_p;

/* **** project includes */

//#include "soc_omap_5912.h"

//#include "csx_mmio.h"
#include "csx.h"

#include "csx_mmio_reg_t.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

typedef struct soc_omap_timer_t {
	csx_p					csx;

	uint64_t				cycle;

	uint32_t				load;
	uint32_t				count;
	
	union {
		struct {
			uint32_t			ar:1;
			uint32_t			clock_enable:1;
			uint32_t			free:1;
			uint32_t			ptv:3;
			uint32_t			st:1;
		};
		uint32_t				value;
	}cntl;
}soc_omap_timer_t;

/* **** */

int soc_omap_timer_init(csx_p csx, soc_omap_timer_h timer, int i);
