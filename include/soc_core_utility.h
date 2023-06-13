#pragma once

#include "config.h"

/* **** */

#include "soc.h"

/* **** */

#include "csx.h"
#include "csx_statistics.h"

/* **** */

#include "bitfield.h"
#include "log.h"

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

static inline uint32_t _soc_core_ifetch(soc_core_p core, uint32_t va, size_t size) {
	static uint32_t splat = 0;
	
	const uint32_t data = csx_mmu_ifetch(core->csx, va, size);
	
	if(0 == data) {
		splat++;
		if(16 <= splat) {
			LOG_ACTION(core->csx->state = CSX_STATE_HALT);
		}
	} else
		splat = 0;

	return(data);
}


static inline uint32_t _soc_core_ifetch_profile(soc_core_p core, uint32_t va, size_t size) {
	const uint64_t dtime = _profile_soc_core_ifetch ? get_dtime() : 0;

	const uint32_t data = _soc_core_ifetch(core, va, size);

	CSX_PROFILE_STAT_COUNT(soc_core.ifetch, dtime);

 	return(data);
}

static inline uint32_t soc_core_ifetch(soc_core_p core, uint32_t va, size_t size) {
	if(_profile_soc_core_ifetch)
		return(_soc_core_ifetch_profile(core, va, size));

	return(_soc_core_ifetch(core, va, size));
}

static inline uint32_t _soc_core_read(soc_core_p core, uint32_t va, size_t size) {
	return(csx_mmu_read(core->csx, va, size));
}

static inline uint32_t _soc_core_read_profile(soc_core_p core, uint32_t va, size_t size)
{
	const uint64_t dtime = _profile_soc_core_read ? get_dtime() : 0;

	const uint32_t data = _soc_core_read(core, va, size);

	CSX_PROFILE_STAT_COUNT(soc_core.read, dtime);

	return(data);
}

static inline uint32_t soc_core_read(soc_core_p core, uint32_t va, size_t size)
{
	if(_profile_soc_core_read)
		return(_soc_core_read_profile(core, va, size));

	return(_soc_core_read(core, va, size));
}

static inline void _soc_core_write(soc_core_p core, uint32_t va, size_t size, uint32_t data)
{
	csx_mmu_write(core->csx, va, size, data);
}

static inline void _soc_core_write_profile(soc_core_p core, uint32_t va, size_t size, uint32_t data)
{
	const uint64_t dtime = _profile_soc_core_write ? get_dtime() : 0;

	_soc_core_write(core, va, size, data);

	CSX_PROFILE_STAT_COUNT(soc_core.write, dtime);
}

static inline void soc_core_write(soc_core_p core, uint32_t va, size_t size, uint32_t data)
{
	if(_profile_soc_core_write)
		_soc_core_write_profile(core, va, size, data);
	else
		_soc_core_write(core, va, size, data);
}
