#include "soc_core_cp15.h"

#include "soc_core_arm_decode.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"

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

		_vCR(_CP15_CRn1_CRm0_OP2x0) = data;
	} else {
		DEBUG(LOG("READ -- Control Register"));
	}

	return(data);
	UNUSED(opcode);
}

/* **** */

static uint32_t _soc_core_cp15_cn2_cm0_op2x0(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	const csx_p csx = core->csx;

	uint32_t data = write ? *write : TTBR0;
	
	if(write) {
		LOG_START("Translation Table Base 0\n\t");
		_LOG_("TTBR0: 0x%05x", mlBFEXT(data, 31, 14));
		_LOG_(" SBZ: 0x%03x", mlBFEXT(data, 13, 5));
		_LOG_(" RGN: %01u", mlBFEXT(data, 4, 3));
		_LOG_(" IMP: %01u", BEXT(data, 2));
		_LOG_(" %c", BEXT(data, 1) ? 'S' : 's');
		LOG_END(" %c", BEXT(data, 0) ? 'C' : 'c');

		TTBR0 = data;
	} else {
		DEBUG(LOG("READ -- Translation Table Base 0"));
	}

	return(data);
	UNUSED(opcode);
}

static uint32_t _soc_core_cp15_cn3_cm0_op2x0(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	const csx_p csx = core->csx;

	uint32_t data = write ? *write : _vCR(_DACR);

	if(write) {
		LOG_START("Domain Access Control Register\n\t");
		uint i = 15;
		do {
			_LOG_("D%02u(%01u)", i, data >> (i << 1) & 3);
			if(i) {
				_LOG_(", ");
			}
		}while(i--);
		LOG_END();
		_vCR(_DACR) = data;
	} else {
		DEBUG(LOG("Domain Access Control Register"));
	}

	return(data);
	UNUSED(opcode);
}

/* **** */

static uint32_t _soc_core_cp15_cn5_cm0_op2x0(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	const csx_p csx = core->csx;

	uint32_t data = write ? *write : _vCR(_DFSR);

	if(write) {
		LOG_START("Fault Status Register: DFSR\n\t");
		_LOG_("0[31:12](0x%03x)", mlBFEXT(data, 31, 12));
		_LOG_(", %s", BEXT(data, 11) ? "WR" : "wr");
		_LOG_(", %s", BEXT(data, 10) ? "FS" : "fs");
		_LOG_(", 0(%01u):0(%01u)", BEXT(data, 9), BEXT(data, 8));
		_LOG_(", DOMAIN: %01u", mlBFEXT(data, 7, 4));
		LOG_END(", STATUS: %01u", mlBFEXT(data, 3, 0));
		
		_vCR(_DFSR) = data;
	} else {
		DEBUG(LOG("READ -- Fault Status Register: DFSR"));
	}

	return(data);
	UNUSED(opcode);
}

/* **** */

static uint32_t _soc_core_cp15_cn7_cm5_op2x0(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	if(write) {
		IF_USER_MODE(UNDEFINED_INSTRUCTION);
		LOG("Invalidate ICache");
	} else {
		DEBUG(LOG("XX READ -- Invalidate ICache"));
	}

	return(0);
	UNUSED(opcode);
}

static uint32_t _soc_core_cp15_cn7_cm7_op2x0(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	if(write) {
		IF_USER_MODE(UNDEFINED_INSTRUCTION);
		LOG("Invalidate ICache and DCache");
	} else {
		DEBUG(LOG("XX READ -- Invalidate ICache and DCache"));
	}

	return(0);
	UNUSED(opcode);
}

static uint32_t _soc_core_cp15_cn7_cm10_op2x3(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	uint32_t data = write ? *write : 0;
	
	if(write) {
		DEBUG(LOG("Cache, Test and Clean"));
	} else {
		LOG("Cache, Test and Clean");
		data = (CPSR & SOC_CORE_PSR_NZCV) | SOC_CORE_PSR_Z;
	}

	return(data);
	UNUSED(opcode);
}

static uint32_t _soc_core_cp15_cn7_cm10_op2x4(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	if(write) {
		IF_USER_MODE(UNDEFINED_INSTRUCTION);
		LOG("Drain write buffer");
	} else {
		DEBUG(LOG("XX READ -- Drain write buffer"));
	}

	return(0);
	UNUSED(opcode);
}
		
/* **** */

static uint32_t _soc_core_cp15_cn8_cm5_op2x0(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	if(write) {
		LOG("Invalidate instruction TLB");
		soc_tlb_invalidate_instruction(core->csx->tlb);
	} else {
		DEBUG(LOG("XX READ -- Invalidate instruction TLB"));
	}

	return(0);
	UNUSED(opcode);
}

static uint32_t _soc_core_cp15_cn8_cm7_op2x0(soc_core_p core, uint32_t opcode, uint32_t* write)
{
	if(write) {
		LOG("Invalidate TLB");
		soc_tlb_invalidate_all(core->csx->tlb);
	} else {
		DEBUG(LOG("XX READ -- Invalidate TLB"));
	}

	return(0);
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
		case cp15(0, 2, 0, 0):
			return(_soc_core_cp15_cn2_cm0_op2x0(core, opcode, write));
		case cp15(0, 3, 0, 0):
			return(_soc_core_cp15_cn3_cm0_op2x0(core, opcode, write));
		case cp15(0, 5, 0, 0):
			return(_soc_core_cp15_cn5_cm0_op2x0(core, opcode, write));
		case cp15(0, 7, 5, 0):
			return(_soc_core_cp15_cn7_cm5_op2x0(core, opcode, write));
		case cp15(0, 7, 7, 0):
			return(_soc_core_cp15_cn7_cm7_op2x0(core, opcode, write));
		case cp15(0, 7, 10, 3):
			return(_soc_core_cp15_cn7_cm10_op2x3(core, opcode, write));
		case cp15(0, 7, 10, 4):
			return(_soc_core_cp15_cn7_cm10_op2x4(core, opcode, write));
		case cp15(0, 8, 5, 0):
			return(_soc_core_cp15_cn8_cm5_op2x0(core, opcode, write));
		case cp15(0, 8, 7, 0):
			return(_soc_core_cp15_cn8_cm7_op2x0(core, opcode, write));
	}

	return(__soc_core_cp15_fault(core, opcode, write));
}

int soc_core_cp15_init(csx_p csx)
{
	int err = 0;

	return(err);

	UNUSED(csx);
}
