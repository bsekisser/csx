#pragma once

/* **** */

#include "soc.h"

/* **** */

#include "csx.h"
#include "csx_statistics.h"

/* **** */

#define CYCLE core->csx->cycle

static inline int _check_sbo(uint32_t opcode, uint8_t msb, uint8_t lsb, uint32_t *test, uint32_t *result)
{
	uint32_t set_bit_count = (msb + 1) - lsb;
	uint32_t set_bit_mask = (1 << set_bit_count) - 1;

	uint32_t ttest, rresult;

	ttest = set_bit_mask << lsb;
	rresult = opcode & ttest;

	if(test)
		*test = ttest;

	if(result)
		*result = rresult;

	return(ttest != rresult);
}

static inline int _check_sbz(uint32_t opcode, uint8_t msb, uint8_t lsb, uint32_t *test, uint32_t *result)
{
	uint32_t set_bit_count = (msb + 1) - lsb;
	uint32_t set_bit_mask = (1 << set_bit_count) - 1;

	uint32_t ttest, rresult;

	ttest = set_bit_mask << lsb;
	rresult = opcode & ttest;

	if(test)
		*test = ttest;

	if(result)
		*result = rresult;

	return(0 != rresult);
}

static inline uint32_t soc_core_ifetch(soc_core_p core, uint32_t va, size_t size)
{
	uint32_t data = 0;
	const uint64_t dtime = _profile_soc_core_ifetch ? get_dtime() : 0;

	if(_use_csx_mem_access)
		data = csx_mmu_ifetch_ma(core->csx, va, size);
	else
		data = csx_mmu_ifetch(core->csx, va, size);

	if(_profile_soc_core_ifetch)
		CSX_PROFILE_STAT_COUNT(soc_core.ifetch, dtime);

 	return(data);
}

static inline uint32_t soc_core_read(soc_core_p core, uint32_t va, size_t size)
{
 	uint32_t data = 0;
	const uint64_t dtime = _profile_soc_core_read ? get_dtime() : 0;

	if(_use_csx_mem_access)
		data = csx_mmu_read_ma(core->csx, va, size);
	else
		data = csx_mmu_read(core->csx, va, size);

	if(_profile_soc_core_read)
		CSX_PROFILE_STAT_COUNT(soc_core.read, dtime);

	return(data);
}

 static inline void soc_core_write(soc_core_p core, uint32_t va, uint32_t data, size_t size)
{
	const uint64_t dtime = _profile_soc_core_write ? get_dtime() : 0;

	if(_use_csx_mem_access)
		csx_mmu_write_ma(core->csx, va, data, size);
	else
		csx_mmu_write(core->csx, va, data, size);

	if(_profile_soc_core_write)
		CSX_PROFILE_STAT_COUNT(soc_core.write, dtime);
}
