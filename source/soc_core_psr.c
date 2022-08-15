#include "soc_core_psr.h"

#include "soc_core_trace.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

#define		CPSR_(_ccf)	(CPSR & SOC_CORE_PSR_ ## _ccf)

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

uint8_t soc_core_check_cc(soc_core_p core, uint8_t cc)
{
	const uint32_t psr = CPSR;

	CORE_T(CCx.s = inst_ccs[cc]);

	uint32_t res = 0;
	switch(cc)
	{
		case INST_CC_EQ:
			res = psr & SOC_CORE_PSR_Z;
			break;
		case INST_CC_NE:
			res = !(psr & SOC_CORE_PSR_Z);
			break;
		case INST_CC_CSHS:
			res = psr & SOC_CORE_PSR_C;
			break;
		case INST_CC_CCLO:
			res = !(psr & SOC_CORE_PSR_C);
			break;
		case INST_CC_MI:
			res = psr & SOC_CORE_PSR_N;
			break;
		case INST_CC_PL:
			res = !(psr & SOC_CORE_PSR_N);
			break;
		case INST_CC_VS:
			res = psr & SOC_CORE_PSR_V;
			break;
		case INST_CC_VC:
			res = !(psr & SOC_CORE_PSR_V);
			break;
		case INST_CC_HI:
			res = (psr & SOC_CORE_PSR_C) | (!(psr & SOC_CORE_PSR_Z));
			break;
		case INST_CC_LS:
			res = (!(psr & SOC_CORE_PSR_C)) | (psr & SOC_CORE_PSR_Z);
			break;
		case INST_CC_GE:
			res = !!(psr & SOC_CORE_PSR_N) == !!(psr & SOC_CORE_PSR_V);
			break;
		case INST_CC_LT:
			res = !!(psr & SOC_CORE_PSR_N) != !!(psr & SOC_CORE_PSR_V);
			break;
		case INST_CC_GT:
			res = (!(psr & SOC_CORE_PSR_Z)) && (!!(psr & SOC_CORE_PSR_N) == !!(psr & SOC_CORE_PSR_V));
			break;
		case INST_CC_LE:
			res = (psr & SOC_CORE_PSR_Z) && (!!(psr & SOC_CORE_PSR_N) != !!(psr & SOC_CORE_PSR_V));
			break;
		case INST_CC_AL:
			res = 1;
			break;
		case INST_CC_NV:
			res = 0;
			break;
		default:
			CORE_TRACE("IR = 0x%08x, cc = %02x, cpsr = 0x%08x, cpsr_cc %02x",
				IR, cc, CPSR, mlBFEXT(CPSR, 31, 28));
			LOG_ACTION(core->csx->state |= CSX_STATE_HALT);
			exit(1);
			break;
	}

	return(!!res);
}

void soc_core_flags_nz(soc_core_p core, uint32_t rd_v)
{
	CPSR &= ~SOC_CORE_PSR_NZ;
	
	CPSR |= BMOV(rd_v, 31, SOC_CORE_PSR_BIT_N);
	CPSR |= ((rd_v == 0) ? SOC_CORE_PSR_Z : 0);
	
	if(1) LOG("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & SOC_CORE_PSR_N), !!(CPSR & SOC_CORE_PSR_Z),
		!!(CPSR & SOC_CORE_PSR_C), !!(CPSR & SOC_CORE_PSR_V));
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

static void _soc_core_flags_nzcv(soc_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v)
{
	const uint32_t xvec = (s1_v ^ s2_v);
	const uint32_t ovec = (s1_v ^ rd_v) & ~xvec;

	CPSR &= ~SOC_CORE_PSR_NZCV;

	CPSR |= BMOV(rd_v, 31, SOC_CORE_PSR_BIT_N);
	CPSR |= ((rd_v == 0) ? SOC_CORE_PSR_Z : 0);

	CPSR |= BMOV((xvec ^ ovec ^ rd_v), 31, SOC_CORE_PSR_BIT_C);
	CPSR |= BMOV(ovec, 31, SOC_CORE_PSR_BIT_V);

	if(1) CORE_TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & SOC_CORE_PSR_N), !!(CPSR & SOC_CORE_PSR_Z),
		!!(CPSR & SOC_CORE_PSR_C), !!(CPSR & SOC_CORE_PSR_V));
}

#if 0
static uint32_t _soc_core_flags_nzcv_add(soc_core_p core, uint32_t s1_v, uint32_t s2_v, int carry_in)
{
//	uint32_t res = s1_v + s2_v + carry_in;
	_soc_core_flags_nzcv(core, res, s1_v, s2_v);

//	return(res);
}
#endif

void soc_core_flags_nzcv_add(soc_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v)
{
	_soc_core_flags_nzcv(core, rd_v, s1_v, s2_v);
}

void soc_core_flags_nzcv_sub(soc_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v)
{
	_soc_core_flags_nzcv(core, rd_v, s1_v, ~s2_v + 1);
}
