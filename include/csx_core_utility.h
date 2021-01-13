#pragma once

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

static inline uint32_t _ror(uint32_t data, uint8_t shift)
{
	uint32_t l = data >> shift;
	uint32_t r = data << (32 - shift);
	
	return(l | r);
}
