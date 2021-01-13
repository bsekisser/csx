#include "csx.h"
#include "csx_core.h"

uint32_t csx_reg_pc_fetch_step(csx_core_p core, uint8_t size, uint32_t *pc)
{
	int thumb = BEXT(CPSR, CSX_PSR_BIT_T);
	*pc = core->pc = (core->reg[rPC] & (~3 >> thumb));
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
			v= (v & ((~3) >> thumb));
		}	break;
		case INSN_PC:
		{
			int thumb = v & 1;
			BMAS(CPSR, CSX_PSR_BIT_T, thumb);
			core->step = thumb ? csx_core_thumb_step : csx_core_arm_step;
			v= (v & ((~3) >> thumb));
		}	break;
	}
	
	core->reg[rr] = v;
}

enum {
	CSX_PSR_MODE_USER = 0x10,
	CSX_PSR_MODE_FIQ,
	CSX_PSR_MODE_IRQ,
	CSX_PSR_MODE_SUPERVISOR,
	CSX_PSR_MODE_ABORT = 0x17,
	CSX_PSR_MODE_UNDEFINED = (0x18 + 0x03),
	CSX_PSR_MODE_SYSTEM = (0x18 + 0x07),
};

void csx_psr_mode_switch(csx_core_p core, uint32_t v)
{
	uint8_t old_mode = BFEXT(core->cpsr, 4, 0);
	uint8_t new_mode = BFEXT(v, 4, 0);

	uint32_t *src = 0, *dst = 0;
	uint8_t sreg;

	if(0) LOG("old_mode = 0x%03x, new_mode = 0x%03x", old_mode, new_mode);

	switch(old_mode)
	{
		case CSX_PSR_MODE_ABORT:
			dst = &core->abt_reg[0];
			sreg = 13;
			break;
		case CSX_PSR_MODE_FIQ:
			dst = &core->fiq_reg[0];
			sreg = 8;
			break;
		case CSX_PSR_MODE_IRQ:
			dst = &core->irq_reg[0];
			sreg = 13;
			break;
		case CSX_PSR_MODE_SUPERVISOR:
			dst = &core->svc_reg[0];
			sreg = 13;
			break;
		case CSX_PSR_MODE_UNDEFINED:
			dst = &core->und_reg[0];
			sreg = 13;
			break;
		case CSX_PSR_MODE_SYSTEM:
		case CSX_PSR_MODE_USER:
			dst = 0;
			break;
		default:
			LOG_ACTION(exit(1));
			break;
	}
		
	src = &core->reg[sreg];

	if(dst) for(int i = sreg; i < 15; i++)
	{
		uint32_t tmp = *dst;
		*dst++ = *src;
		*src++ = tmp;
	}
	
	switch(new_mode)
	{
		case CSX_PSR_MODE_ABORT:
			src = &core->abt_reg[0];
			sreg = 13;
			break;
		case CSX_PSR_MODE_FIQ:
			src = &core->fiq_reg[0];
			sreg = 8;
			break;
		case CSX_PSR_MODE_IRQ:
			src = &core->irq_reg[0];
			sreg = 13;
			break;
		case CSX_PSR_MODE_SUPERVISOR:
			src = &core->svc_reg[0];
			sreg = 13;
			break;
		case CSX_PSR_MODE_UNDEFINED:
			src = &core->und_reg[0];
			sreg = 13;
			break;
		case CSX_PSR_MODE_SYSTEM:
		case CSX_PSR_MODE_USER:
			src = 0;
			break;
		default:
			LOG_ACTION(exit(1));
			break;
	}

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

