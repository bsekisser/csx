#define rLR 14
#define rPC 15

#define INSN_PC (0x10 | (rPC))

/* **** */

uint32_t csx_reg_get(csx_core_p core, csx_reg_t r);
void csx_reg_set(csx_core_p core, csx_reg_t r, uint32_t v);
