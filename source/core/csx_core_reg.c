#include "csx.h"
#include "csx_core.h"

uint32_t csx_reg_get(csx_core_p core, csx_reg_t r)
{
	uint32_t res = core->reg[r & 0x0f];

	switch(r)
	{
		case INSN_PC:
			core->pc = res;
			break;
		case rPC:
			res += (2 << (0 == (core->cpsr & CSX_PSR_T)));
			break;
	}

	return(res);
}

void csx_reg_set(csx_core_p core, csx_reg_t r, uint32_t v)
{
	uint8_t rr = r & 0x0f;
	
	switch(r)
	{
		case INSN_PC:
			LOG_ACTION(core->pc = v);
			break;
		case rPC:
			if(v & 1)
			{
				v &= ~1;

				core->cpsr |= CSX_PSR_T;
				core->csx->step = csx_core_thumb_step;
			}
			break;
	}
	
//	if(BIT_OF(core->mode_regs, rr))
		core->reg[rr] = v;
//	else
	
}

enum {
	CSX_PSR_MODE_USER = 0,
	CSX_PSR_MODE_FIQ,
	CSX_PSR_MODE_IRQ,
	CSX_PSR_MODE_SUPERVISOR,
	CSX_PSR_MODE_ABORT = 0x07,
	CSX_PSR_MODE_UNDEFINED = (0x08 + 0x03),
	CSX_PSR_MODE_SYSTEM = (0x08 + 0x07),
};

void csx_psr_mode_switch(csx_core_p core, uint32_t v)
{
	uint8_t old_mode = _bits(core->cpsr, 4, 0) & 0x0f;
	uint8_t new_mode = _bits(v, 4, 0) & 0x0f;

	uint32_t *src, *dst;
	uint8_t sreg;

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
	}
		
	src = &core->reg[sreg];

	if((old_mode != CSX_PSR_MODE_USER)
		&& (old_mode != CSX_PSR_MODE_SYSTEM))
			*dst++ = core->spsr;

	for(int i = sreg; i < 15; i++)
		*dst++ = *src++;
	
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
	}

	if((new_mode != CSX_PSR_MODE_USER)
		&& (new_mode != CSX_PSR_MODE_SYSTEM))
		core->spsr = *src++;
	else
		core->spsr = 0;

	dst = &core->reg[sreg];
	
	for(int i = sreg; i < 15; i++)
		*dst++ = *src++;
}
