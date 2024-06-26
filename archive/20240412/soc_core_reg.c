#include "soc_core_reg.h"

#include "soc_core_arm.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"
#include "soc_core_thumb.h"
#include "soc_core_trace.h"
#include "soc_core_utility.h"
#include "soc_core.h"

#include "csx.h"

#include "arm_cpsr.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/log.h"

/* **** */

static uint32_t* soc_core_psr_mode_regs(soc_core_p core, uint8_t mode, soc_core_reg_p reg)
{
	*reg = 13;

	const unsigned arm32_mode = CPSR_C(32) | mode;

//	switch(_arm_pc26 ? mode : arm32_mode)
	switch(mode)
	{
		case CPSR_M32(Abort):
			return(&core->abt_reg[0]);
			break;
		case CPSR_M32(FIQ):
			*reg = 8;
			return(&core->fiq_reg[0]);
			break;
		case CPSR_M32(IRQ):
			return(&core->irq_reg[0]);
			break;
		case CPSR_M32(Supervisor):
			return(&core->svc_reg[0]);
			break;
		case CPSR_M32(Undefined):
			return(&core->und_reg[0]);
			break;
		case CPSR_M32(System):
		case CPSR_M32(User):
			break;

		case CPSR_M26(FIQ):
		case CPSR_M26(IRQ):
		case CPSR_M26(Supervisor):
		case CPSR_M26(System):
		case CPSR_M26(User):
			LOG("mode = 0x%03x", mode);
			LOG_ACTION(return(soc_core_psr_mode_regs(core, arm32_mode, reg)));
//			LOG_ACTION(UNIMPLIMENTED);
			break;

		default:
			LOG("mode = 0x%03x", mode);
			LOG_ACTION(UNDEFINED);
			break;
	}

	*reg = 0;
	return(0);
}

uint32_t soc_core_reg_pc_fetch_step_arm(soc_core_p core)
{
	if(_check_pedantic_pc)
		assert(PC & 1);

	const unsigned pc_msb = (IF_CPSR_C(32) ? 30 : 25);
	
	IP = mlBFTST(PC, pc_msb, 2);
	PC = mlBFBIC_MAS(PC, PC + 4, pc_msb, 2);
	
	return(soc_core_ifetch(core, IP, sizeof(uint32_t)));
}

uint32_t soc_core_reg_pc_fetch_step_thumb(soc_core_p core)
{
	IP = PC & ~1U;
	PC += 2;

	return(soc_core_ifetch(core, IP, sizeof(uint16_t)));
}

static uint32_t soc_core_reg_get_pc26(soc_core_p core, uint32_t res)
{
	const unsigned mask = mlBF(31, 26) | 3;
	res &= mask;
	res |= CPSR & mask;
	BSET_AS(res, 27, BEXT_CPSR_C(IRQ));
	BSET_AS(res, 26, BEXT_CPSR_C(FIQ));

	return(res);
}

uint32_t soc_core_reg_get(soc_core_p core, soc_core_reg_t r)
{
	uint32_t res = core->reg[r];

	if(rPC == r) {
		int thumb = IF_CPSR_C(32) && BEXT_CPSR_C(T);

		const unsigned pc_msb = (IF_CPSR_C(32) ? 31 : 25);
		const unsigned pc_lsb = 2 >> thumb;

		res = mlBFBIC_MAS(res, res + (4 >> thumb), pc_msb, pc_lsb);
		if(_arm_pc26 && (0 == IF_CPSR_C(32)))
			return(soc_core_reg_get_pc26(core, res));
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

	const unsigned pc_msb = IF_CPSR_C(32) ? 31 : 25;

	PC = mlBFTST(PC, pc_msb, (2 >> thumb));
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
	const uint8_t old_mode = mlBFEXT(CPSR, 4, 0);
	const uint8_t new_mode = mlBFEXT(v, 4, 0) | CPSR_C(32);

	if(old_mode == new_mode)
		return;

	if(_trace_psr_switch)
		soc_core_trace_psr(core, 0, CPSR);

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

	CPSR = mlBFINS(CPSR, new_mode, 4, 0);

	if(_trace_psr_switch)
		soc_core_trace_psr(core, 0, CPSR);
}

