#include "soc_core_cp15.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"
#include "soc_core_reg.h"
#include "soc_core.h"

#include "csx_soc_exception.h"
#include "csx.h"

#include "arm_cpsr.h"

/* **** */

#include "bitfield.h"
#include "callback_qlist.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

enum {
	_csx_soc_exception_fsr_mask = mlBF(7, 4) | mlBF(3, 0),
};

enum {
	_FSR_DFSR,
	_FSR_IFSR,
//
	__FSR_COUNT,
};

typedef struct csx_soc_exception_t {
	csx_p csx;
	soc_core_p core;

	uint32_t far;
	uint32_t fsr[2];

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}csx_soc_exception_t;

typedef struct exception_t* exception_p;
typedef struct exception_t {
	uint32_t cpsr_clear;
	uint32_t cpsr_set;
	uint32_t pc;
}exception_t;

static exception_t exception_list[_EXCEPTION_COUNT] = {
	[_EXCEPTION_DataAbort] = {
		CPSR_C(Thumb),
		CPSR_M(Abort) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x10, },
	[_EXCEPTION_FIQ] = {
		CPSR_C(Thumb),
		CPSR_M(FIQ) | CPSR_C(FIQ) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x1c, },
	[_EXCEPTION_IRQ] = {
		CPSR_C(Thumb),
		CPSR_M(IRQ) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x18, },
	[_EXCEPTION_PrefetchAbort] = {
		CPSR_C(Thumb),
		CPSR_M(Abort) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x0c, },
	[_EXCEPTION_Reset] = {
		CPSR_C(Thumb),
		CPSR_M(Supervisor) | CPSR_C(FIQ) | CPSR_C(IRQ) | CPSR_C(Abort) | CPSR_C(E),
		0x00, },
	[_EXCEPTION_SWI] = {
		CPSR_C(Thumb),
		CPSR_C(IRQ) | CPSR_C(E),
		0x08, },
	[_EXCEPTION_UndefinedInstruction] = {
		CPSR_C(Thumb),
		CPSR_C(IRQ) | CPSR_C(E),
		0x04, },
};

/* **** */

static void _csx_soc_exception(csx_p csx, soc_core_p core, unsigned type)
{
	switch(type) {
		case _EXCEPTION_DataAbort:
		case _EXCEPTION_PrefetchAbort:
			fflush(stderr);
			fflush(stdout);
			assert((CPSR_C(Abort) | CPSR_C(IRQ)) & ~CPSR);
			break;
		case _EXCEPTION_FIQ:
			assert((CPSR_C(FIQ) | CPSR_C(IRQ)) & ~CPSR);
			break;
		case _EXCEPTION_IRQ:
			assert(CPSR_C(IRQ) & ~CPSR);
			break;
	}

	switch(type) {
		case _EXCEPTION_DataAbort:
			csx->cxu->far = IP;
			PC = IP + 8;
			break;
		case _EXCEPTION_PrefetchAbort:
			PC = IP + 4;
			break;
	}

	const uint32_t saved_cpsr = CPSR;
	const uint32_t saved_pc = PC;

	const exception_p exception = &exception_list[type];

	soc_core_psr_mode_switch(core, exception->cpsr_set);

	LR = saved_pc;

	if(SPSR)
		*SPSR = saved_cpsr;

	CPSR &= ~exception->cpsr_clear;
	CPSR |= exception->cpsr_set;

	const unsigned cpsr_c_e = exception->cpsr_set & CPSR_C(E);
	const unsigned cpsr_c_e_set = cpsr_c_e && CP15_reg1_bit(ee);

	BSET_AS(CPSR, _CPSR_C_BIT_E, cpsr_c_e_set);

	switch(type) {
		case _EXCEPTION_FIQ:
		case _EXCEPTION_IRQ:
			if(CP15_reg1_VEbit) { // ????
				LOG_ACTION(IMPLIMENTATION_DEFINED);
				break;
			}
		__attribute__((fallthrough));
		default:
			PC = exception->pc;
			if(CP15_reg1_bit(v))
				PC |= ~0xffff;
			break;
	}
}

static int _csx_soc_exception_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	const csx_soc_exception_h h2cxu = param;
//	csx_soc_exception_h cp = *h2cxu;

	handle_free(param);

	return(0);
}

static int _csx_soc_exception_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

//	const csx_soc_exception_p cxu = param;

	return(0);
	UNUSED(param);
}


static uint32_t _csx_soc_exception_cp15_access_fsr(csx_soc_exception_p cxu,
	uint32_t* write, unsigned fsr)
{
	const uint32_t data = write ? *write : cxu->fsr[fsr];
	const char* fsr_string[__FSR_COUNT] = {
		[_FSR_DFSR] = "DFSR",
		[_FSR_IFSR] = "IFSR",
	};

	if(*write) {
		LOG_START("Fault Status Register: %s\n\t", fsr_string[fsr]);
		_LOG_("0[31:12](0x%03x)", mlBFEXT(data, 31, 12));
		_LOG_(", %s", BEXT(data, 11) ? "WR" : "wr");
		_LOG_(", %s", BEXT(data, 10) ? "FS" : "fs");
		_LOG_(", 0(%01u):0(%01u)", BEXT(data, 9), BEXT(data, 8));
		_LOG_(", DOMAIN: %01u", mlBFEXT(data, 7, 4));
		LOG_END(", STATUS: %01u", mlBFEXT(data, 3, 0));

		assert(!mlBFTST(data, 31, 8));

		cxu->fsr[fsr] = data & ~_csx_soc_exception_fsr_mask;
	}

	return(data);
}

static uint32_t _csx_soc_exception_cp15_access_far(void* param, uint32_t* write)
{
	const csx_soc_exception_p cxu = param;

	const uint32_t data = write ? *write : cxu->far;

	if(*write) {
		assert(!mlBFTST(data, 31, 8));

		cxu->far = data;
	}

	return(data);
}

static uint32_t _csx_soc_exception_cp15_access_fsr_dfsr(void* param, uint32_t* write)
{
	return(_csx_soc_exception_cp15_access_fsr(param, write, _FSR_DFSR));
}
static uint32_t _csx_soc_exception_cp15_access_fsr_ifsr(void* param, uint32_t* write)
{
	return(_csx_soc_exception_cp15_access_fsr(param, write, _FSR_IFSR));
}

/* **** */

void csx_exception(csx_p csx, unsigned type)
{
	_csx_soc_exception(csx, csx->core, type);
}

csx_soc_exception_p csx_soc_exception_alloc(csx_p csx, csx_soc_exception_h h2cxu)
{
	ERR_NULL(csx);
	ERR_NULL(h2cxu);

	if(_trace_alloc) {
		LOG();
	}

	const csx_soc_exception_p cxu = handle_calloc((void*)h2cxu, 1, sizeof(csx_soc_exception_t));
	ERR_NULL(cxu);

	cxu->csx = csx;

	/* **** */

	csx_callback_atexit(csx, &cxu->atexit, _csx_soc_exception_atexit, h2cxu);
	csx_callback_atreset(csx, &cxu->atreset, _csx_soc_exception_atreset, cxu);

	/* **** */

	return(cxu);
}

void csx_soc_exception_init(csx_soc_exception_p cxu)
{
	ERR_NULL(cxu);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	const csx_coprocessor_p cp = cxu->csx->cp;

	csx_coprocessor_register_access(cp, cp15(0, 5, 0, 0),
		_csx_soc_exception_cp15_access_fsr_dfsr, cxu);
	csx_coprocessor_register_access(cp, cp15(0, 5, 0, 1),
		_csx_soc_exception_cp15_access_fsr_ifsr, cxu);
	csx_coprocessor_register_access(cp, cp15(0, 6, 0, 0),
		_csx_soc_exception_cp15_access_far, cxu);
}

/* **** */

void soc_core_exception(soc_core_p core, unsigned type)
{
	_csx_soc_exception(core->csx, core, type);
}

void soc_exception_init(csx_soc_p soc, csx_soc_exception_p cxu)
{
	ERR_NULL(soc);
	ERR_NULL(cxu);

	if(_trace_init) {
		LOG();
	}

	/* ***** */

//	cxu->soc = soc;
}
