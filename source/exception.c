#include "soc_core_cp15.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"
#include "soc_core_reg.h"
#include "soc_core.h"

#include "exception.h"

#include "csx.h"

#include "arm_cpsr.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

#include <stdint.h>

/* **** */

typedef struct exception_t* exception_p;
typedef struct exception_t {
	uint32_t cpsr_clear;
	uint32_t cpsr_set;
	uint32_t pc;
}exception_t;

static exception_t exception_list[_EXCEPTION_COUNT] = {
	[_EXCEPTION_DataAbort] = {
		CPSR_C(Thumb),
		CPSR_M(Abort) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x10, },
	[_EXCEPTION_FIQ] = {
		CPSR_C(Thumb),
		CPSR_M(FIQ) | CPSR_C(FIQ) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x1c, },
	[_EXCEPTION_IRQ] = {
		CPSR_C(Thumb),
		CPSR_M(IRQ) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x18, },
	[_EXCEPTION_PrefetchAbort] = {
		CPSR_C(Thumb),
		CPSR_M(Abort) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x0c, },
	[_EXCEPTION_Reset] = {
		CPSR_C(Thumb),
		CPSR_M(Supervisor) | CPSR_C(FIQ) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x00, },
	[_EXCEPTION_SWI] = {
		CPSR_C(Thumb),
		CPSR_C(IRQ) | CPSR_C(E),
		0x08, },
	[_EXCEPTION_UndefinedInstruction] = {
		CPSR_C(Thumb),
		CPSR_C(IRQ) | CPSR_C(E),
		0x04, },
};

/* **** */

static void _csx_soc_exception(csx_p csx, soc_core_p core, unsigned type)
{
	switch(type) {
		case _EXCEPTION_DataAbort:
			PC = IP + 8;
			break;
		case _EXCEPTION_PrefetchAbort:
			PC = IP + 4;
			break;
	}

	const uint32_t saved_cpsr = CPSR;
	const uint32_t saved_pc = PC;

	const exception_p exception = &exception_list[type];

	soc_core_psr_mode_switch(core, exception->cpsr_set);

	LR = saved_pc;

	if(SPSR)
		*SPSR = saved_cpsr;

	const uint32_t cpsr_mask = exception->cpsr_clear | exception->cpsr_set;

	CPSR &= ~cpsr_mask;
	CPSR |= (exception->cpsr_set & ~CPSR_C(E));

	if(exception->cpsr_set & CPSR_C(E)) {
		BSET_AS(CPSR, _CPSR_C_BIT_E, !!CP15_reg1_bit(ee));
	}

	switch(type) {
		case _EXCEPTION_FIQ:
		case _EXCEPTION_IRQ:
			if(CP15_reg1_VEbit) { // ????
				LOG_ACTION(IMPLIMENTATION_DEFINED);
				break;
			}
		__attribute__((fallthrough));
		default:
			PC = exception->pc;
			if(CP15_reg1_bit(v))
				PC |= ~0xffff;
			break;
	}
}

/* **** */

void csx_exception(csx_p csx, unsigned type)
{
	_csx_soc_exception(csx, csx->core, type);
}

/* **** */

void soc_core_exception(soc_core_p core, unsigned type)
{
	_csx_soc_exception(core->csx, core, type);
}
