#pragma once 

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

#include <stdint.h>

/* **** */

static shifter_operand_t _arm_dpi_sop_r_s(uint8_t sop, uint8_t r, uint8_t shift)
{
	shift &= _BM(1 + (11 - 7));
//	shift >>= 1;
	
	uint32_t out = (shift << 7) | ((sop & 3) << 5) | (r & 0x0f);
	
	return((shifter_operand_t)out);
}

/* **** */

shifter_operand_t arm_dpi_asr_r_s(uint8_t r, uint8_t shift)
{
	return(_arm_dpi_sop_r_s(SOC_CORE_SHIFTER_OP_ASR, r, shift));
}

shifter_operand_t arm_dpi_lsl_r_s(uint8_t r, uint8_t shift)
{
	return(_arm_dpi_sop_r_s(SOC_CORE_SHIFTER_OP_LSL, r, shift));
}

shifter_operand_t arm_dpi_lsr_r_s(uint8_t r, uint8_t shift)
{
	return(_arm_dpi_sop_r_s(SOC_CORE_SHIFTER_OP_LSR, r, shift));
}

shifter_operand_t arm_dpi_ror_i_s(uint8_t i, uint8_t shift)
{
	i &= _BM(1 + (7 - 0));

	shift >>= 1;
	shift &= _BM(1 + (11 - 8));
	
	uint32_t out = _BV(15) | (shift << 8) | i;

	if(0) LOG("i = 0x%08x, shift = 0x%08x, shifter_operand = 0x%08x", i, shift, out);

	return((shifter_operand_t)out);
}
