#include "csx_test_utility.h"

#include "csx_soc.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/log.h"

/* **** */

void _cxx(csx_test_p t, uint32_t value, size_t size)
{
	csx_write(t->csx, pc(t), size, value);
	t->pc += size;
}

int _test_cpsr_xpsr(csx_test_p t, unsigned cpsr, unsigned xpsr)
{
	return(_test_cpsr_xpsr_mask(t, cpsr, xpsr, SOC_CORE_PSR_NZCV));
}

int _test_cpsr_xpsr_mask(csx_test_p t, unsigned cpsr, unsigned xpsr, unsigned mask)
{
	unsigned test_cpsr = cpsr & mask;
	unsigned test_xpsr = xpsr & mask;
	
	if(test_cpsr != test_xpsr) {
		TRACE_PSR(cpsr);
		TRACE_PSR(xpsr);

		return(0);
	}

	return(1);

	UNUSED(t);
}

int _test_nzc(csx_test_p t, int n, int z, int c)
{
	soc_core_p core = t->core;
	
	unsigned xpsr = _BSET_AS(0, SOC_CORE_PSR_BIT_N, !!n);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_Z, !!z);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_C, !!c);
	
	return(_test_cpsr_xpsr_mask(t, CPSR, xpsr, SOC_CORE_PSR_NZC));
}

int _test_nzcv(csx_test_p t, int n, int z, int c, int v)
{
	soc_core_p core = t->core;
	
	unsigned xpsr = _BSET_AS(0, SOC_CORE_PSR_BIT_N, !!n);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_Z, !!z);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_C, !!c);
		BSET_AS(xpsr, SOC_CORE_PSR_BIT_V, !!v);
	
	return(_test_cpsr_xpsr(t, CPSR, xpsr));
}

uint32_t _test_value(unsigned i)
{
	uint32_t test_value = i;
	
	if(65536 > i)
		test_value |= test_value << 16;

	if(256 > i)
		test_value |= test_value << 8;
	
	if(16 > i)
		test_value |= test_value << 4;

	return(test_value);
}

/* **** */

uint32_t pc(csx_test_p t)
{
	return(t->pc);
}
