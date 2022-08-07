#include "csx.h"
#include "csx_core.h"
#include "csx_core_utility.h"

enum {
	CSX_PSR_MODE_USER = 0x10,
	CSX_PSR_MODE_FIQ,
	CSX_PSR_MODE_IRQ,
	CSX_PSR_MODE_SUPERVISOR,
	CSX_PSR_MODE_ABORT = 0x17,
	CSX_PSR_MODE_UNDEFINED = (0x18 + 0x03),
	CSX_PSR_MODE_SYSTEM = (0x18 + 0x07),
};

static uint32_t* csx_psr_mode_regs(csx_core_p core, uint8_t mode, csx_reg_p reg)
{
	*reg = 13;
	
	switch(mode)
	{
		case CSX_PSR_MODE_ABORT:
			return(&core->abt_reg[0]);
			break;
		case CSX_PSR_MODE_FIQ:
			*reg = 8;
			return(&core->fiq_reg[0]);
			break;
		case CSX_PSR_MODE_IRQ:
			return(&core->irq_reg[0]);
			break;
		case CSX_PSR_MODE_SUPERVISOR:
			return(&core->svc_reg[0]);
			break;
		case CSX_PSR_MODE_UNDEFINED:
			return(&core->und_reg[0]);
			break;
		case CSX_PSR_MODE_SYSTEM:
		case CSX_PSR_MODE_USER:
			break;
		default:
			LOG("mode = 0x%03x", mode);
			LOG_ACTION(exit(1));
			break;
	}
	
	*reg = 0;
	return(0);
}

uint32_t csx_reg_pc_fetch_step_arm(csx_core_p core)
{
	if(_check_pedantic_pc)
		assert(PC & 1);

	IP = PC & ~3;
	PC += 4;
	
	return(csx_core_read(core, IP, sizeof(uint32_t)));
}

uint32_t csx_reg_pc_fetch_step_thumb(csx_core_p core)
{
	IP = PC & ~1;
	PC += 2;
	
	return(csx_core_read(core, IP, sizeof(uint16_t)));
}

uint32_t csx_reg_get(csx_core_p core, csx_reg_t r)
{
	uint32_t res = core->reg[r];

	if(rPC == r) {
		int thumb = BEXT(CPSR, CSX_PSR_BIT_T);
		res &= (~3 >> thumb);
		res += (4 >> thumb);
	}

	return(res);
}

void csx_reg_set(csx_core_p core, csx_reg_t r, uint32_t v)
{
	if(_check_pedantic_pc)
		assert(rPC != r);

	core->reg[r] = v;
}

void csx_reg_set_pcx(csx_core_p core, uint32_t new_pc)
{
	int thumb = new_pc & 1;
	BMAS(CPSR, CSX_PSR_BIT_T, thumb);
	core->step = thumb ? csx_core_thumb_step : csx_core_arm_step;
	new_pc &= (~3 >> thumb);

	PC = new_pc;
}

uint32_t csx_reg_usr(csx_core_p core, csx_reg_t r, uint32_t* v)
{
	csx_reg_t reg;
	
	const uint8_t mode = mlBFEXT(CPSR, 4, 0);
	uint32_t* usr_regs = csx_psr_mode_regs(core, mode, &reg);

	uint32_t vout = 0;
	if(reg && ((r & 0x0f) < 15) && r >= reg)
	{
		uint8_t umreg = r - reg;
		vout = usr_regs[umreg];
		if(v)
			usr_regs[umreg] = *v;
	}
	else
	{
		vout = csx_reg_get(core, r);
		if(v)
			csx_reg_set(core, r, *v);
	}
	return(vout);	
}

void csx_psr_mode_switch(csx_core_p core, uint32_t v)
{
	const uint8_t old_mode = mlBFEXT(core->cpsr, 4, 0);
	const uint8_t new_mode = mlBFEXT(v, 4, 0);

	uint32_t *src = 0, *dst = 0;
	uint8_t sreg = 0;

	if(0) LOG("old_mode = 0x%03x, new_mode = 0x%03x", old_mode, new_mode);

	dst = csx_psr_mode_regs(core, old_mode, &sreg);
		
	src = &core->reg[sreg];

	if(dst) for(int i = sreg; i < 15; i++)
	{
		uint32_t tmp = *dst;
		*dst++ = *src;
		*src++ = tmp;
	}
	
	src = csx_psr_mode_regs(core, new_mode, &sreg);

	dst = &core->reg[sreg];
	
	if(src) for(int i = sreg; i < 15; i++)
	{
		uint32_t tmp = *dst;
		*dst++ = *src;
		*src++ = tmp;
	}

	core->spsr = src;
	core->cpsr = v;
}

