#pragma once

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

static inline uint32_t _rol(uint32_t data, uint8_t shift)
{
	shift &= 31;
	uint32_t l = data << shift;
	uint32_t r = data >> ((-shift) & 31);
	
	return(l | r);
}

static inline uint32_t _ror(uint32_t data, uint8_t shift)
{
	shift &= 31;
	uint32_t l = data >> shift;
	uint32_t r = data << ((-shift) & 31);
	
	return(l | r);
}

static inline uint32_t soc_core_read(soc_core_p core, uint32_t va, size_t size)
{
	return(csx_soc_read(core->csx, va, size));
}

static inline void soc_core_write(soc_core_p core, uint32_t va, uint32_t data, size_t size)
{
	csx_soc_write(core->csx, va, data, size);
}
