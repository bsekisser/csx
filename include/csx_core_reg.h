enum {
	rSP = 13,
	rLR = 14,
	rPC = 15,
};

#define LR							core->reg[rLR]

#define PC							core->reg[rPC]
#define PC_ARM						((PC + 4) & ~3)
#define PC_THUMB					((PC + 2) & ~1)

#define SP							core->reg[rSP]

/* **** */

uint32_t csx_reg_pc_fetch_step_arm(csx_core_p core);
uint32_t csx_reg_pc_fetch_step_thumb(csx_core_p core);

uint32_t csx_reg_get(csx_core_p core, csx_reg_t r);

void csx_reg_set(csx_core_p core, csx_reg_t r, uint32_t v);
void csx_reg_set_pcx(csx_core_p core, uint32_t new_pc);

uint32_t csx_reg_usr(csx_core_p core, csx_reg_t r, uint32_t* v);

void csx_psr_mode_switch(csx_core_p core, uint32_t v);
