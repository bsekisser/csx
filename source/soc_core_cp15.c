#include "soc_core_cp15.h"

#include "soc_core_arm_decode.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"

/* **** */

#include "csx_soc_exception.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#undef DEBUG
//#define DEBUG(_x) _x
#ifndef DEBUG
	#define DEBUG(_x)
#endif

#define IF_USER_MODE(_action) \
	if(IS_USER_MODE) { \
		_action; \
	}

#define IS_USER_MODE (0 == soc_core_in_a_privaleged_mode(core))

#define cp15_crm(_crm) \
	((_crm) & 15)

#define cp15_crn(_crn) \
	(((_crn) & 15) << 16)

#define cp15_op1(_op1) \
	(((_op1) & 7) << 21)

#define cp15_op2(_op2) \
	(((_op2) & 7) << 5)

#undef cp15
#define cp15(_op1, _n, _m, _op2) \
	(cp15_op1(_op1) | cp15_crn(_n) | cp15_crm(_m) | cp15_op2(_op2))

/* **** */

static uint32_t __soc_core_cp15_fault(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	uint32_t data = write ? *write : 0;
	
	LOG_START("-- 0x%08x -- ", opcode);
	_LOG_("CRn = 0x%01x", MCRC_CRn);
	_LOG_(", OP1 = 0x%01x", MCRC_OP1);
	_LOG_(", CRm = 0x%01x", MCRC_CRm);
	_LOG_(", OP2 = 0x%01x", MCRC_OP2);
	LOG_END(", write = %01u(%08x)", write ? 1 : 0, data);

	DECODE_FAULT;
	return(0);
}

/* **** */

static uint32_t _soc_core_cp15_cn1_cm0_op2x0(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	const csx_p csx = core->csx;
	
	uint32_t data = write ? *write : _vCR(_CP15_CRn1_CRm0_OP2x0);

	if(write) {
		LOG_START("Control Register\n\t");
		_LOG_("0(0x%01x)", mlBFEXT(data, 31, 27));
		_LOG_(":%c2", BEXT(data, 26) ? 'L' : 'l');
		_LOG_(":%s", BEXT(data, 25) ? "EE" : "ee");
		_LOG_(":%s", BEXT(data, 24) ? "VE" : "ve");
		_LOG_(":%s", BEXT(data, 23) ? "XP" : "xp");
		_LOG_(":%c", BEXT(data, 22) ? 'U' : 'u');
		_LOG_(":%s", BEXT(data, 23) ? "FI" : "fi");
		_LOG_(":0(%s)", BEXT(data, 20) ? "ST" : "st");
		_LOG_(":0(%01u)", BEXT(data, 19));
		_LOG_(":1(%s)", BEXT(data, 18) ? "IT" : "it");
		_LOG_(":0(%01u)", BEXT(data, 17));
		_LOG_(":1(%s)", BEXT(data, 16) ? "DT" : "dt");
		_LOG_(":%c4", BEXT(data, 15) ? 'L' : 'l');
		_LOG_(":%s", BEXT(data, 14) ? "RR" : "rr");
		_LOG_(":%c", BEXT(data, 13) ? 'V' : 'v');
		_LOG_(":%c", BEXT(data, 12) ? 'I' : 'i');
		if(1) {
			_LOG_(":%c", BEXT(data, 11) ? 'Z' : 'z');
			_LOG_(":%c", BEXT(data, 10) ? 'F' : 'f');
		} else
			_LOG_(":0(%01u)", mlBFEXT(data, 11, 10));
		_LOG_(":%c", BEXT(data, 9) ? 'R' : 'r');
		_LOG_(":%c", BEXT(data, 8) ? 'S' : 's');
		_LOG_(":%c", BEXT(data, 7) ? 'B' : 'b');
		if(1) {
			_LOG_(":%c", BEXT(data, 6) ? 'L' : 'l');
			_LOG_(":%c", BEXT(data, 5) ? 'D' : 'd');
			_LOG_(":%c", BEXT(data, 4) ? 'P' : 'p');
			_LOG_(":%c", BEXT(data, 3) ? 'W' : 'w');
		} else
			_LOG_(":1(%01u)", mlBFEXT(data, 6, 3));
		_LOG_(":%c", BEXT(data, 2) ? 'C' : 'c');
		_LOG_(":%c", BEXT(data, 1) ? 'A' : 'a');
		LOG_END(":%c", BEXT(data, 0) ? 'M' : 'm');

		unsigned bits_set = (_vCR(_CP15_CRn1_CRm0_OP2x0) ^ data) & data;
		_vCR(_CP15_CRn1_CRm0_OP2x0) = data;

		if(0 && BEXT(bits_set, 0))
			csx_mmu_dump_ttbr0(csx);

		if(CP15_reg1_EEbit) {
			LOG("CP15_reg1_EEbit -- XXX");
		}
	} else {
		DEBUG(LOG("READ -- Control Register"));
	}

	return(data);
	UNUSED(opcode);
}

/* **** */

uint32_t soc_core_cp15(soc_core_p core, uint32_t* write)
{
	const uint32_t mask = cp15(~0, ~0, ~0, ~0);
	const uint32_t opcode = IR & mask;

	switch(opcode) {
		case cp15(0, 1, 0, 0):
			return(_soc_core_cp15_cn1_cm0_op2x0(core, opcode, write));
	}

	return(__soc_core_cp15_fault(core, opcode, write));
}

int soc_core_cp15_init(csx_p csx)
{
	int err = 0;

	return(err);

	UNUSED(csx);
}
