#include "soc_core_decode.h"

#include "soc_core_arm_decode.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"
#include "soc_core_shifter.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/log.h"
#include "libbse/include/shift_roll.h"

/* **** */

void soc_core_arm_decode_coproc(soc_core_p core)
{
	rR(D) = MCRC_Rd;
	rR(M) = MCRC_CRm;
	rR(N) = MCRC_CRn;
}
