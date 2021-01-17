#include "csx.h"
#include "csx_core.h"

enum {
	CSX_PSR_MODE_USER = 0x10,
	CSX_PSR_MODE_FIQ,
	CSX_PSR_MODE_IRQ,
	CSX_PSR_MODE_SUPERVISOR,
	CSX_PSR_MODE_ABORT = 0x17,
	CSX_PSR_MODE_UNDEFINED = (0x18 + 0x03),
	CSX_PSR_MODE_SYSTEM = (0x18 + 0x07),
};

static uint32_t* csx_psr_mode_regs(csx_core_p core, uint8_t mode, uint8_t *reg)
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
			LOG_ACTION(exit(1));
			break;
	}
	
	*reg = 0;
	return(0);
}

uint32_t csx_reg_pc_fetch_step(csx_core_p core, uint32_t *pc)
{
	int thumb = BEXT(CPSR, CSX_PSR_BIT_T);
	core->pc = (core->reg[rPC] & (~3 >> thumb));
	if(pc)
		*pc = core->pc;
	uint8_t size = (4 >> thumb);
	core->reg[rPC] += size;
	
	return(csx_mmu_read(core->csx->mmu, *pc, size));
}

uint32_t csx_reg_get(csx_core_p core, csx_reg_t r)
{
	uint32_t res = core->reg[r & 0x0f];

	switch(r)
	{
		case rPC:
		{
			int thumb = BEXT(CPSR, CSX_PSR_BIT_T);
			res &= (~3 >> thumb);
			res += (4 >> thumb);
		}	break;
		case TEST_PC:
			break;
	}

	return(res);
}

void csx_reg_set(csx_core_p core, csx_reg_t r, uint32_t v)
{
	uint8_t rr = r & 0x0f;
	
	switch(r)
	{
		case rPC:
		{
			int thumb = BEXT(CPSR, CSX_PSR_BIT_T);
			v &= (~3 >> thumb);
		}	break;
		case INSN_PC:
		{
			int thumb = v & 1;
			BMAS(CPSR, CSX_PSR_BIT_T, thumb);
			core->step = thumb ? csx_core_thumb_step : csx_core_arm_step;
			v &= (~3 >> thumb);
		}	break;
	}
	
	core->reg[rr] = v;
}

uint32_t csx_reg_usr(csx_core_p core, csx_reg_t r, uint32_t* v)
{
	uint8_t reg;
	uint8_t mode = BFEXT(CPSR, 4, 0);
	uint32_t* usr_regs = csx_psr_mode_regs(core, mode, &reg);

	uint32_t vout;
	if(reg && r >= reg)
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
	uint8_t old_mode = BFEXT(core->cpsr, 4, 0);
	uint8_t new_mode = BFEXT(v, 4, 0);

	uint32_t *src = 0, *dst = 0;
	uint8_t sreg;

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

