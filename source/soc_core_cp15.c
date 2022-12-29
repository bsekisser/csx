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

#define sli(_d, _v, _s) (((_d) << _s) | ((_v) & _BM(_s)))

#define cp15(_op1, _n, _m, _op2) \
	sli(sli(sli(sli(0, _op1, 4), _n, 4), _m, 4), _op2, 4)

uint32_t soc_core_cp15_read(soc_core_p core)
{
	const csx_p csx = core->csx;

	const uint opcode = cp15(MCRC_OP1, rR(N), rR(M), MCRC_OP2);

	uint32_t data = vCR(rR(N));

	switch(opcode) {
		case cp15(0, 7, 10, 3):
			LOG("Cache, Test and Clean");
			data = (CPSR & SOC_CORE_PSR_NZCV) | SOC_CORE_PSR_Z;
			break;
	}
	
	return(data);
}

void soc_core_cp15_write(soc_core_p core)
{
	const csx_p csx = core->csx;
	
	const uint opcode = cp15(MCRC_OP1, rR(N), rR(M), MCRC_OP2);

	switch(opcode) {
		case cp15(0, 1, 0, 0):
			LOG("Control Register");
			if(1) {
				LOG_START("SBZ(0x%03x)", mlBFEXT(vR(D), 31, 27));
				_LOG_(":%c2", BEXT(vR(D), 26) ? 'L' : 'l');
				_LOG_(":%s", BEXT(vR(D), 25) ? "EE" : "ee");
				_LOG_(":%s", BEXT(vR(D), 24) ? "VE" : "ve");
				_LOG_(":%s", BEXT(vR(D), 23) ? "XP" : "xp");
				_LOG_(":%c", BEXT(vR(D), 22) ? 'U' : 'u');
				_LOG_(":%s", BEXT(vR(D), 23) ? "FI" : "fi");
				_LOG_(":?(%01u)?", mlBFEXT(vR(D), 20, 19));
			} else
				LOG_START("SBZ(0x%03x)", mlBFEXT(vR(D), 31, 19));
			_LOG_(":SBO(%01u)", BEXT(vR(D), 18));
			_LOG_(":SBZ(%01u)", BEXT(vR(D), 17));
			_LOG_(":SBO(%01u)", BEXT(vR(D), 16));
			_LOG_(":%c4", BEXT(vR(D), 15) ? 'L' : 'l');
			_LOG_(":%s", BEXT(vR(D), 14) ? "RR" : "rr");
			_LOG_(":%c", BEXT(vR(D), 13) ? 'V' : 'v');
			_LOG_(":%c", BEXT(vR(D), 12) ? 'I' : 'i');
			if(1) {
				_LOG_(":%c", BEXT(vR(D), 11) ? 'Z' : 'z');
				_LOG_(":%c", BEXT(vR(D), 10) ? 'F' : 'f');
			} else
				_LOG_(":SBZ(%02u)", mlBFEXT(vR(D), 11, 10));
			_LOG_(":%c", BEXT(vR(D), 9) ? 'R' : 'r');
			_LOG_(":%c", BEXT(vR(D), 8) ? 'S' : 's');
			_LOG_(":%c", BEXT(vR(D), 7) ? 'B' : 'b');
			if(1) {
				_LOG_(":%c", BEXT(vR(D), 6) ? 'L' : 'l');
				_LOG_(":%c", BEXT(vR(D), 5) ? 'D' : 'd');
				_LOG_(":%c", BEXT(vR(D), 4) ? 'P' : 'p');
				_LOG_(":%c", BEXT(vR(D), 3) ? 'W' : 'w');
			} else
				_LOG_(":SBO(%01u)", mlBFEXT(vR(D), 6, 3));
			_LOG_(":%c", BEXT(vR(D), 2) ? 'C' : 'c');
			_LOG_(":%c", BEXT(vR(D), 1) ? 'A' : 'a');
			LOG_END(":%c", BEXT(vR(D), 0) ? 'M' : 'm');
//			if(BEXT(vR(D), 0))
//				soc_tlb_invalidate_all(csx->tlb);
			break;
		case cp15(0, 2, 0, 0):
			LOG_START("Translation Table Base 0\n\t");
			_LOG_("TTBR0: 0x%05x", mlBFEXT(vR(D), 31, 14));
			_LOG_(" SBZ: 0x%03x", mlBFEXT(vR(D), 13, 5));
			_LOG_(" RGN: %01u", mlBFEXT(vR(D), 4, 3));
			_LOG_(" IMP: %01u", BEXT(vR(D), 2));
			_LOG_(" %c", BEXT(vR(D), 1) ? 'S' : 's');
			LOG_END(" %c", BEXT(vR(D), 0) ? 'C' : 'c');
			break;
		case cp15(0, 3, 0, 0):
			LOG_START("Domain access control\n\t");
			for(int i = 15; i > 0; i--)
				_LOG_("D%02u: %01u ", i, mlBFEXT(vR(D), (i << 1), ((i << 1) - 1)));
			LOG_END();
			break;
		case cp15(0, 5, 0, 0):
			LOG("Fault Status Register: %s", MCRC_OP2 ? "IFSR" : "DFSR");
			LOG_START("SBZ: 0x%05x", mlBFEXT(vR(D), 31, 9));
			_LOG_(", 0: %01u", BEXT(vR(D), 8));
			_LOG_(", DOMAIN: %01u", mlBFEXT(vR(D), 7, 4));
			LOG_END(", STATUS: %01u", mlBFEXT(vR(D), 3, 0));
			break;
		case cp15(0, 7, 5, 0):
			LOG("Invalidate ICache");
			break;
		case cp15(0, 7, 7, 0):
			LOG("Invalidate ICache and DCache");
			break;
		case cp15(0, 7, 10, 4):
			LOG("Drain write buffer");
			break;
		case cp15(0, 8, 5, 0):
			LOG("Invalidate instruction TLB");
			soc_tlb_invalidate_instruction(csx->tlb);
			break;
		case cp15(0, 8, 7, 0):
			LOG("Invalidate TLB");
			soc_tlb_invalidate_all(csx->tlb);
			break;
		default:
			LOG("opcode = 0x%08x", opcode);
			soc_core_disasm_arm(core, PC, IR);
			LOG_ACTION(exit(-1));
			break;
	}

	vCR(rR(N)) = vR(D);
}

int soc_core_cp15_init(csx_p csx)
{
	int err = 0;

	return(err);

	UNUSED(csx);
}
