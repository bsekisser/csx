#include "csx_test_utility.h"

#include "soc.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

int _test_cpsr_xpsr(csx_test_p t, uint cpsr, uint xpsr)
{
	return(_test_cpsr_xpsr_mask(t, cpsr, xpsr, SOC_CORE_PSR_NZCV));
}

int _test_cpsr_xpsr_mask(csx_test_p t, uint cpsr, uint xpsr, uint mask)
{
	uint test_cpsr = cpsr & mask;
	uint test_xpsr = xpsr & mask;
	
	if(test_cpsr != test_xpsr) {
		TRACE_PSR(cpsr);
		TRACE_PSR(xpsr);

		return(0);
	}

	return(1);

	UNUSED(t);
}

void _assert_cpsr_xpsr(csx_test_p t, uint cpsr, uint xpsr)
{
	assert(_test_cpsr_xpsr(t, cpsr, xpsr));
}

void _assert_cpsr_xpsr_mask(csx_test_p t, uint cpsr, uint xpsr, uint mask)
{
	assert(_test_cpsr_xpsr_mask(t, cpsr, xpsr, mask));
}

void _assert_nzc(csx_test_p t, int n, int z, int c)
{
	soc_core_p core = t->csx->core;
	
	uint xpsr = _BSET_AS(0, SOC_CORE_PSR_BIT_N, !!n);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_Z, !!z);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_C, !!c);
	
	_assert_cpsr_xpsr_mask(t, CPSR, xpsr, SOC_CORE_PSR_NZC);
}

void _assert_nzcv(csx_test_p t, int n, int z, int c, int v)
{
	soc_core_p core = t->csx->core;
	
	uint xpsr = _BSET_AS(0, SOC_CORE_PSR_BIT_N, !!n);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_Z, !!z);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_C, !!c);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_V, !!v);
	
	_assert_cpsr_xpsr(t, CPSR, xpsr);
}

void _cxx(csx_test_p t, uint32_t value, size_t size)
{
	csx_write(t->csx, pc(t), size, value);
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
