#include "csx.h"
#include "csx_core.h"

/* **** */

#define		CPSR_(_ccf)	(CPSR & CSX_PSR_ ## _ccf)

/* **** */

enum {
	INST_CC_EQ = 0,
	INST_CC_NE,
	INST_CC_CSHS,
	INST_CC_CCLO,
	INST_CC_MI,
	INST_CC_PL,
	INST_CC_VS,
	INST_CC_VC,
	INST_CC_HI,
	INST_CC_LS,
	INST_CC_GE,
	INST_CC_LT,
	INST_CC_GT,
	INST_CC_LE,
	INST_CC_AL,
	INST_CC_NV
};


static const char* inst_ccs[16] = {
	"EQ", "NE", "HS", "LO", "MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT", "GT", "LE", "AL", "XX"
};

uint8_t csx_core_check_cc(csx_core_p core, uint32_t opcode, uint8_t cc)
{
	const uint32_t psr = CPSR;

	core->ccs = inst_ccs[cc];

	uint32_t res = 0;
	switch(cc)
	{
		case INST_CC_EQ:
			res = psr & CSX_PSR_Z;
			break;
		case INST_CC_NE:
			res = !(psr & CSX_PSR_Z);
			break;
		case INST_CC_CSHS:
			res = psr & CSX_PSR_C;
			break;
		case INST_CC_CCLO:
			res = !(psr & CSX_PSR_C);
			break;
		case INST_CC_MI:
			res = psr & CSX_PSR_N;
			break;
		case INST_CC_PL:
			res = !(psr & CSX_PSR_N);
			break;
		case INST_CC_VS:
			res = psr & CSX_PSR_V;
			break;
		case INST_CC_VC:
			res = !(psr & CSX_PSR_V);
			break;
		case INST_CC_HI:
			res = (psr & CSX_PSR_C) | (!(psr & CSX_PSR_Z));
			break;
		case INST_CC_LS:
			res = (!(psr & CSX_PSR_C)) | (psr & CSX_PSR_Z);
			break;
		case INST_CC_GE:
			res = !!(psr & CSX_PSR_N) == !!(psr & CSX_PSR_V);
			break;
		case INST_CC_LT:
			res = !!(psr & CSX_PSR_N) != !!(psr & CSX_PSR_V);
			break;
		case INST_CC_GT:
			res = (!(psr & CSX_PSR_Z)) && (!!(psr & CSX_PSR_N) == !!(psr & CSX_PSR_V));
			break;
		case INST_CC_LE:
			res = (psr & CSX_PSR_Z) && (!!(psr & CSX_PSR_N) != !!(psr & CSX_PSR_V));
			break;
		case INST_CC_AL:
			res = 1;
			break;
		case INST_CC_NV:
			res = 0;
			break;
		default:
			TRACE("opcode = 0x%08x, cc = %02x, cpsr = 0x%08x, cpsr_cc %02x",
				opcode, cc, CPSR, BFEXT(CPSR, 31, 28));
			LOG_ACTION(core->csx->state |= CSX_STATE_HALT);
			exit(1);
			break;
	}

	return(!!res);
}

void csx_core_flags_nz(csx_core_p core, uint32_t rd_v)
{
	CPSR &= ~CSX_PSR_NZ;
	
	CPSR |= BMOV(rd_v, 31, CSX_PSR_BIT_N);
	CPSR |= ((rd_v == 0) ? CSX_PSR_Z : 0);
	
	if(0) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & CSX_PSR_N), !!(CPSR & CSX_PSR_Z),
		!!(CPSR & CSX_PSR_C), !!(CPSR & CSX_PSR_V));
}

/*
 * Credit to:
 * 		http://www.emulators.com/docs/nx11_flags.htm
 *
 * OF(A+B) = ((A XOR D) AND NOT (A XOR B)) < 0
 * OF(A-B) = ((A XOR D) AND (A XOR B)) < 0
 *
 * CF(A+B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND NOT (A XOR B)) < 0)
 * CF(A-B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND (A XOR B)) < 0)
 * 
 */

static void _csx_core_flags_nzcv(csx_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v, uint8_t is_add)
{
	CPSR &= ~CSX_PSR_NZCV;
	
	CPSR |= BMOV(rd_v, 31, CSX_PSR_BIT_N);
	CPSR |= ((rd_v == 0) ? CSX_PSR_Z : 0);
	
	const uint32_t xvec = (s1_v ^ s2_v);
	uint32_t ovec;

	if(is_add)
	{
		ovec = (s1_v ^ rd_v) & ~xvec;
		CPSR |= BMOV((xvec ^ ovec ^ rd_v), 31, CSX_PSR_BIT_C);
	}
	else
	{
		ovec = (s1_v ^ rd_v) & xvec;
		CPSR |= BMOV((xvec ^ ovec), 31, CSX_PSR_BIT_C);
	}
		
	CPSR |= BMOV(ovec, 31, CSX_PSR_BIT_V);

	if(0) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & CSX_PSR_N), !!(CPSR & CSX_PSR_Z),
		!!(CPSR & CSX_PSR_C), !!(CPSR & CSX_PSR_V));
}

void csx_core_flags_nzcv_add(csx_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v)
{
	_csx_core_flags_nzcv(core, rd_v, s1_v, s2_v, 1);
}

void csx_core_flags_nzcv_sub(csx_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v)
{
	_csx_core_flags_nzcv(core, rd_v, s1_v, s2_v, 0);
}
