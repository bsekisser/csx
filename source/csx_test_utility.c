#include "csx_test_utility.h"

#include "soc.h"

/* **** */

#include "bitfield.h"

/* **** */

void _assert_cpsr_xpsr(csx_test_p t, uint cpsr, uint xpsr)
{
	cpsr &= mlBF(31, 28);
	xpsr &= mlBF(31, 28);
	
	assert(cpsr == xpsr);
}

void _assert_nzcv(csx_test_p t, int n, int z, int c, int v)
{
	soc_core_p core = t->csx->core;
	
	assert(n == BEXT(CPSR, SOC_CORE_PSR_BIT_N));
	assert(z == BEXT(CPSR, SOC_CORE_PSR_BIT_Z));
	assert(c == BEXT(CPSR, SOC_CORE_PSR_BIT_C));
	assert(v == BEXT(CPSR, SOC_CORE_PSR_BIT_V));
}

void _cxx(csx_test_p t, uint32_t value, uint8_t size)
{
	csx_soc_write(t->csx, pc(t), value, size);
	t->pc += size;
}

uint32_t _test_value(uint8_t i)
{
	uint32_t test_value = i | i << 16;

	test_value |= test_value << 4;
	test_value |= test_value << 8;

	return(test_value);
}

/* **** */

uint32_t pc(csx_test_p t)
{
	return(t->pc);
}
