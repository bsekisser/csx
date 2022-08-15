#pragma once

/* **** */

typedef struct soc_mmio_gp_timer_t** soc_mmio_gp_timer_h;
typedef struct soc_mmio_gp_timer_t* soc_mmio_gp_timer_p;

/* **** */

#include "csx.h"

/* **** */

typedef struct soc_mmio_gp_timer_t {
	csx_p			csx;
	soc_mmio_p		mmio;
	
	struct {
		uint32_t	ctrl;
		uint32_t	interrupt_enable;
		uint32_t	load;
		uint32_t	match;
		uint32_t	ocp_cfg;
		uint32_t	syncro_icr;
		uint32_t	status;
		uint32_t	wakeup_enable;
	}timer[7];
}soc_mmio_gp_timer_t;

int soc_mmio_gp_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_gp_timer_h h2gpt);
