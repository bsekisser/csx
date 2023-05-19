#include "soc_core_reg.h"

#include "soc_core_arm.h"
#include "soc_core_psr.h"
#include "soc_core_thumb.h"
#include "soc_core_utility.h"
#include "soc_core.h"

#include "csx.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

enum {
	PSR_MODE_USER = 0x10,
	PSR_MODE_FIQ,
	PSR_MODE_IRQ,
	PSR_MODE_SUPERVISOR,
	PSR_MODE_ABORT = 0x17,
	PSR_MODE_UNDEFINED = (0x18 + 0x03),
	PSR_MODE_SYSTEM = (0x18 + 0x07),
};

static uint32_t* soc_core_psr_mode_regs(soc_core_p core, uint8_t mode, soc_core_reg_p reg)
{
	*reg = 13;
	
	switch(mode)
	{
		case PSR_MODE_ABORT:
			return(&core->abt_reg[0]);
			break;
		case PSR_MODE_FIQ:
			*reg = 8;
			return(&core->fiq_reg[0]);
			break;
		case PSR_MODE_IRQ:
			return(&core->irq_reg[0]);
			break;
		case PSR_MODE_SUPERVISOR:
			return(&core->svc_reg[0]);
			break;
		case PSR_MODE_UNDEFINED:
			return(&core->und_reg[0]);
			break;
		case PSR_MODE_SYSTEM:
		case PSR_MODE_USER:
			break;
		default:
			LOG("mode = 0x%03x", mode);
			LOG_ACTION(exit(1));
			break;
	}
	
	*reg = 0;
	return(0);
}

uint32_t soc_core_reg_pc_fetch_step_arm(soc_core_p core)
{
	if(_check_pedantic_pc)
		assert(PC & 1);

	IP = PC & ~3;
	PC += 4;
	
	return(soc_core_ifetch(core, IP, sizeof(uint32_t)));
}

uint32_t soc_core_reg_pc_fetch_step_thumb(soc_core_p core)
{
	IP = PC & ~1;
	PC += 2;
	
	return(soc_core_ifetch(core, IP, sizeof(uint16_t)));
}

uint32_t soc_core_reg_get(soc_core_p core, soc_core_reg_t r)
{
	uint32_t res = core->reg[r];

	if(rPC == r) {
		int thumb = BEXT(CPSR, SOC_CORE_PSR_BIT_T);
		res &= (~3 >> thumb);
		res += (4 >> thumb);
	}

	return(res);
}

void soc_core_reg_set(soc_core_p core, soc_core_reg_t r, uint32_t v)
{
	if(_check_pedantic_pc)
		assert(rPC != r);

	core->reg[r] = v;
}

typedef void (*step_fn)(soc_core_p);

void soc_core_reg_set_pcx(soc_core_p core, uint32_t new_pc)
{
	PC = new_pc;
	soc_core_reg_set_thumb(core, PC & 1);
}

void soc_core_reg_set_thumb(soc_core_p core, int thumb)
{
	step_fn step_fn_list[2][2] = {
		{ soc_core_arm_step, soc_core_arm_step_profile, },
		{ soc_core_thumb_step, soc_core_thumb_step_profile, },
	};
	
	BMAS(CPSR, SOC_CORE_PSR_BIT_T, thumb);
	core->step = step_fn_list[thumb][_profile_soc_core_step];
	PC &= (~3 >> thumb);
}

uint32_t soc_core_reg_usr(soc_core_p core, soc_core_reg_t r, uint32_t* v)
{
	soc_core_reg_t reg = 0;
	
	const uint8_t mode = mlBFEXT(CPSR, 4, 0);
	uint32_t* usr_regs = soc_core_psr_mode_regs(core, mode, &reg);

	uint32_t vout = 0;
	if(reg && ((r & 0x0f) < 15) && r >= reg)
	{
		const uint8_t umreg = r - reg;
		vout = usr_regs[umreg];
		if(v)
			usr_regs[umreg] = *v;
	}
	else
	{
		vout = soc_core_reg_get(core, r);
		if(v)
			soc_core_reg_set(core, r, *v);
	}
	return(vout);	
}

void soc_core_psr_mode_switch(soc_core_p core, uint32_t v)
{
	const uint8_t old_mode = mlBFEXT(core->cpsr, 4, 0);
	const uint8_t new_mode = mlBFEXT(v, 4, 0);

	if(old_mode == new_mode)
		return;

	uint32_t *src = 0, *dst = 0;
	uint8_t sreg = 0;

	if(0) LOG("old_mode = 0x%03x, new_mode = 0x%03x", old_mode, new_mode);

	dst = soc_core_psr_mode_regs(core, old_mode, &sreg);
		
	src = &core->reg[sreg];

	if(dst) for(int i = sreg; i < 15; i++)
	{
		const uint32_t tmp = *dst;
		*dst++ = *src;
		*src++ = tmp;
	}
	
	src = soc_core_psr_mode_regs(core, new_mode, &sreg);

	dst = &core->reg[sreg];
	
	if(src) for(int i = sreg; i < 15; i++)
	{
		const uint32_t tmp = *dst;
		*dst++ = *src;
		*src++ = tmp;
	}

	core->spsr = src;
	core->cpsr = v;
}

