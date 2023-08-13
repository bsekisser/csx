#include "soc_core_psr.h"

#include "soc_core_trace.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

static const char* inst_ccs[16] = {
	"EQ", "NE", "HS", "LO", "MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT", "GT", "LE", "AL", "XX"
};

#define CPSR_(_x) BEXT(CPSR, SOC_CORE_PSR_BIT_##_x)
#define NOT_CPSR_(_x) (!CPSR_(_x))

uint8_t soc_core_check_cc(soc_core_p core, uint8_t cc)
{
	CORE_T(CCx.s = inst_ccs[cc]);

	uint32_t res = 0;

	switch(cc & ~1U)
	{
		case INST_CC_EQ_NE:
			res = CPSR_(Z);
			break;
		case INST_CC_CS_CC:
			res = CPSR_(C);
			break;
		case INST_CC_MI_PL:
			res = CPSR_(N);
			break;
		case INST_CC_VS_VC:
			res = CPSR_(V);
			break;
		case INST_CC_HI_LS:
			res = (CPSR_(C) && NOT_CPSR_(Z));
			break;
		case INST_CC_GE_LT:
			res = (CPSR_(N) == CPSR_(V));
			break;
		case INST_CC_GT_LE:
			res = (NOT_CPSR_(Z) && (CPSR_(N) == CPSR_(V)));
			break;
		case INST_CC_AL_NV:
			res = 1;
			break;
		default:
			CORE_TRACE("IR = 0x%08x, cc = %02x, cpsr = 0x%08x, cpsr_cc %02x",
				IR, cc, CPSR, mlBFEXT(CPSR, 31, 28));
			LOG_ACTION(core->csx->state |= CSX_STATE_HALT);
			exit(1);
			break;
	}

	res = !!res;
	res = (cc & 1) ? !res : res;

	return(res);
}

#define TRACE_CPSR \
	{ \
		LOG("N = %1u, Z = %1u, C = %1u, V = %1u", \
		CPSR_(N), CPSR_(Z), CPSR_(C), CPSR_(V)); \
	}

static void _soc_core_flags_nz(soc_core_p core, uint32_t rd_v)
{
	CPSR |= BMOV(rd_v, 31, SOC_CORE_PSR_BIT_N);
	CPSR |= (!(!!rd_v) << SOC_CORE_PSR_BIT_Z);
}

void soc_core_flags_nz(soc_core_p core, uint32_t rd_v)
{
	CPSR &= ~SOC_CORE_PSR_NZ;
	
	_soc_core_flags_nz(core, rd_v);
	
	if(0) TRACE_CPSR
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

#if 0
static void _soc_core_flags_nzcv(soc_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v)
{
	const uint32_t xvec = (s1_v ^ s2_v);
	const uint32_t ovec = (s1_v ^ rd_v) & ~xvec;

	CPSR &= ~SOC_CORE_PSR_NZCV;

	_soc_core_flags_nz(core, rd_v);

	CPSR |= BMOV((xvec ^ ovec ^ rd_v), 31, SOC_CORE_PSR_BIT_C);
	CPSR |= BMOV(ovec, 31, SOC_CORE_PSR_BIT_V);

	if(0) TRACE_CPSR
}

void soc_core_flags_nzcv_add(soc_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v)
{
	_soc_core_flags_nzcv(core, rd_v, s1_v, s2_v);
}

void soc_core_flags_nzcv_sub(soc_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v)
{
	_soc_core_flags_nzcv(core, rd_v, s1_v, ~s2_v);
}
#endif
