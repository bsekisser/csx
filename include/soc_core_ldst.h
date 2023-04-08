#pragma once

/* **** */

#include "soc_core_arm_decode.h"
#include "soc_core_reg.h"
#include "soc_core_trace.h"
#include "soc_core_utility.h"
#include "soc_core.h"

/* **** */

#include "bitfield.h"
#include "shift_roll.h"

/* **** */

#include <assert.h>
#include <stdint.h>

/* **** */

static void _arm_ldst(soc_core_p core, uint32_t ea)
{
	if(CCx.e) {
		if(LDST_BIT(l20)) {
			if(rR(EA) == sizeof(uint32_t))
				assert(0 == (ea & 3));

			LOG("ea = 0x%08x, size = 0%02x", ea, rR(EA));

			vR(D) = soc_core_read(core, ea, rR(EA));

			LOG(">> 0x%08x", vR(D));

			/*	ARMv5, CP15_r1_Ubit == 0 */
			if(rR(EA) == sizeof(uint32_t))
				vR(D) = _ror(vR(D), ((ea & 3) << 3));
			else {
				if(LDST_FLAG_S) /* sign extend ? */
					vR(D) = mlBFEXTs(vR(D), (rR(EA) << 3), 0);
			}

			if(rPC == rR(D)) {
				CORE_TRACE_BRANCH(vR(D));
				soc_core_reg_set_pcx(core, vR(D));
			} else
				soc_core_reg_set(core, rR(D), vR(D));
		} else {
			if(rR(EA) == sizeof(uint32_t))
				ea &= ~3;
			
			soc_core_write(core, ea, rR(EA), vR(D));
		}
	}
}

static uint32_t _arm_ldst_ea(soc_core_p core, int wb)
{
	vR(EA) = vR(N);

	if(LDST_BIT(u23))
		vR(EA) += vR(N_OFFSET);
	else
		vR(EA) -= vR(N_OFFSET);

	if(wb)
		soc_core_reg_set(core, rR(N), vR(EA));

	if(LDST_BIT(p24))
		return(vR(EA));

	return(vR(N));
}
