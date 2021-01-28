#define rSP 13
#define rLR 14
#define rPC 15

enum {
	_THUMB = 0x04,
	_TEST,
};

#define rTHUMB(_r)		(_BV(_THUMB) | ((_r) & 0x0f))
#define rTEST(_r)		(_BV(_TEST) | ((_r) & 0x0f))

/* **** */

uint32_t csx_reg_pc_fetch_step(csx_core_p core, uint32_t *pc);

uint32_t csx_reg_get(csx_core_p core, csx_reg_t r);
void csx_reg_set(csx_core_p core, csx_reg_t r, uint32_t v);

uint32_t csx_reg_usr(csx_core_p core, csx_reg_t r, uint32_t* v);
