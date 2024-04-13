#pragma once

/* **** */

#include <stdint.h>

/* **** */

typedef uint8_t soc_core_reg_t;
typedef uint8_t* soc_core_reg_p;

/* **** */

#include "csx.h"

/* **** */

enum {
	rSP = 13,
	rLR = 14,
	rPC = 15,
};

#define LR							core->reg[rLR]
#define PC							core->reg[rPC]
#define SP							core->reg[rSP]

/* **** */

uint32_t soc_core_reg_pc_fetch_step_arm(soc_core_p core);
uint32_t soc_core_reg_pc_fetch_step_thumb(soc_core_p core);

uint32_t soc_core_reg_get(soc_core_p core, soc_core_reg_t r);

void soc_core_reg_set(soc_core_p core, soc_core_reg_t r, uint32_t v);
void soc_core_reg_set_pcx(soc_core_p core, uint32_t new_pc);
void soc_core_reg_set_thumb(soc_core_p core, int thumb);

uint32_t soc_core_reg_usr(soc_core_p core, soc_core_reg_t r, uint32_t* v);

void soc_core_psr_mode_switch(soc_core_p core, uint32_t v);
