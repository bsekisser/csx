#pragma once

/* **** */

#include "soc_core_arm_decode.h"
#include "soc_core_cp15.h"
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

static void __arm_ldst_reg_set(soc_core_p core)
{
	if(rPC == rR(D)) {
		CORE_TRACE_BRANCH(vR(D));
		soc_core_reg_set_pcx(core, vR(D));
	} else
		soc_core_reg_set(core, rR(D), vR(D));
}

/* **** */

static void _arm_ldst_bh(soc_core_p core, uint32_t ea, size_t size)
{
	if(LDST_BIT(l20)) {
		vR(D) = soc_core_read(core, ea, size);
		__arm_ldst_reg_set(core);
	} else
		soc_core_write(core, ea, size, vR(D));
}

static void _arm_ldst_d(soc_core_p core, uint32_t ea)
{ /* untested / verified */
	if(BTST(IR, 5)) { /* strd */
		soc_core_write(core, ea, sizeof(uint32_t), vR(D));

		CYCLE++;
		
		vR(D) = soc_core_reg_get(core, rR(D) ^ 1);
		soc_core_write(core, ea + 4, sizeof(uint32_t), vR(D));
	} else { /* ldrd */
		vR(D) = soc_core_read(core, ea, sizeof(uint32_t));
		__arm_ldst_reg_set(core);

		CYCLE++;
		rR(D) ^= 1;

		vR(D) = soc_core_read(core, ea + 4, sizeof(uint32_t));
		__arm_ldst_reg_set(core);
		rR(D) ^= 1;
	}
}

static void _arm_ldst_ldr_sb(soc_core_p core, uint32_t ea)
{
	vR(D) = (int8_t)soc_core_read(core, ea, sizeof(int8_t));
	__arm_ldst_reg_set(core);
}

static void _arm_ldst_ldr_sh(soc_core_p core, uint32_t ea)
{
	vR(D) = (int16_t)soc_core_read(core, ea, sizeof(int16_t));
	__arm_ldst_reg_set(core);
}

static void _arm_ldst_w(soc_core_p core, uint32_t ea)
{
	const csx_p csx = core->csx;

	assert(LDST_BIT(p24) || (0 == LDST_BIT(w21)));
	assert(!((0 == LDST_BIT(p24)) && (1 == LDST_BIT_w21)));

	if(LDST_BIT(l20)) {
		vR(D) = soc_core_read(core, ea, sizeof(uint32_t));
		
		if(CP15_reg1_bit(u))
			vR(D) = _ror(vR(D), ((ea & 3) << 3));
		
		__arm_ldst_reg_set(core);
	} else
		soc_core_write(core, ea, sizeof(uint32_t), vR(D));
}

/* **** */

static void _arm_ldst(soc_core_p core, uint32_t ea)
{
	if(CCx.e) {
		if(LDST_BIT(b22))
			_arm_ldst_bh(core, ea, sizeof(uint8_t));
		else
			_arm_ldst_w(core, ea);
	}
}

static uint32_t _arm_ldst_ea(soc_core_p core)
{
	vR(EA) = vR(N);

	if(LDST_BIT(u23))
		vR(EA) += vR(N_OFFSET);
	else
		vR(EA) -= vR(N_OFFSET);

	if(CCx.e) {
		if((0 == LDST_BIT(p24)) || LDST_BIT(w21))
			soc_core_reg_set(core, rR(N), vR(EA));
	}

	if(LDST_BIT(p24))
		return(vR(EA));

	return(vR(N));
}

static void _arm_ldst_sh(soc_core_p core, uint32_t ea)
{
	if(CCx.e) {
		if(BTST(IR, 6)) {
			if(LDST_BIT(l20)) {
				if(BTST(IR, 5))
					_arm_ldst_ldr_sh(core, ea);
				else
					_arm_ldst_ldr_sb(core, ea);
			} else
				_arm_ldst_d(core, ea);
		} if(BTST(IR, 5))
			_arm_ldst_bh(core, ea, sizeof(uint16_t));
		else {
			DECODE_FAULT
		}
	}
}
