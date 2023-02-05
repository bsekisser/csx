#include "soc_core_decode.h"

#include "soc_core_arm_decode.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"
#include "soc_core_shifter.h"

/* **** */

#include "bitfield.h"
#include "log.h"
#include "shift_roll.h"

/* **** */

void soc_core_arm_decode_coproc(soc_core_p core)
{
	rR(D) = MCRC_Rd;
	rR(M) = MCRC_CRm;
	rR(N) = MCRC_CRn;
}

static const char* shifter_op_string[] = {
	"LSL", "LSR", "ASR", "ROR"
};

const char* soc_core_arm_decode_shifter_op_string(const uint8_t shopc)
{
	return(shifter_op_string[shopc & 0x03]);
}
