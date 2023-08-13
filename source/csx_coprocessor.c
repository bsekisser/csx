#include "config.h"

#include "soc_core_disasm.h"
#include "soc_core.h"

#include "csx_coprocessor.h"
#include "csx_cp15_reg1.h"
#include "csx_mem.h"
#include "csx_soc.h"
#include "csx.h"

/* **** */

#include "bitfield.h"
#include "callback_qlist.h"
#include "err_test.h"
#include "handle.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct csx_coprocessor_access_t* csx_coprocessor_access_p;
typedef struct csx_coprocessor_access_t {
	coprocessor_access_fn fn;
	void* param;
}csx_coprocessor_access_t;

typedef struct csx_cp15_reg1_t* csx_cp15_reg1_p;
typedef struct csx_cp15_reg1_t {
	struct {
		uint32_t clear;
		uint32_t set;
	}on_reset;

	struct {
		uint32_t clear;
		uint32_t set;
	}invalid;
}csx_cp15_reg1_t;

typedef struct csx_coprocessor_t {
	csx_coprocessor_access_t cp15[16][16][7][7];
	soc_core_p core;
	csx_p csx;
	csx_soc_p soc;

	csx_cp15_reg1_t cp15_reg1;

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}csx_coprocessor_t;

/* **** */

static void ___csx_cp15_invalid_clear_set(csx_p csx, csx_coprocessor_p cp, uint32_t* write)
{
	uint32_t data = write ? *write : csx->cp15_reg1;

	data &= cp->cp15_reg1.invalid.clear;
	data |= cp->cp15_reg1.invalid.set;

	csx->cp15_reg1 = data;
}

static int __csx_coprocessor_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	const csx_coprocessor_h h2cp = param;
//	csx_coprocessor_p cp = *h2cp;

	handle_free(param);

	return(0);
}

static int __csx_coprocessor_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	const csx_coprocessor_p cp = param;
	const csx_p csx = cp->csx;

	/* **** */

	csx->cp15_reg1 &= cp->cp15_reg1.on_reset.clear;
	csx->cp15_reg1 |= cp->cp15_reg1.on_reset.set;

	___csx_cp15_invalid_clear_set(csx, cp, 0);

	/* **** */

	return(0);
	UNUSED(param);
}

/* **** */

static csx_coprocessor_access_p _csx_coprocessor_access(csx_coprocessor_p cp, uint32_t ir)
{
	return(&cp->cp15[ir_cp_crn(ir)][ir_cp_crm(ir)][ir_cp_op1(ir)][ir_cp_op2(ir)]);
}

/* **** */

static uint32_t _csx_cp15_0_1_0_0_access(void* param, uint32_t* write)
{
	const csx_coprocessor_p cp = param;
	const csx_p csx = cp->csx;

	uint32_t data = write ? *write : csx->cp15_reg1;

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

		unsigned bits_set = (csx->cp15_reg1 ^ data) & data;
		___csx_cp15_invalid_clear_set(csx, cp, &data);

		if(BTST(bits_set, _CP15_reg1(b))) {
			LOG("CP15_reg1_Bbit -- XXX");
		}

		if(BTST(bits_set, _CP15_reg1(l4))) {
			LOG("CP15_reg1_L4bit -- XXX");
		}

		if(BTST(bits_set, _CP15_reg1(ee))) {
			LOG("CP15_reg1_EEbit -- XXX");
		}

		if(0 && BTST(bits_set, _CP15_reg1_bit(m)))
			soc_mmu_dump_ttbr0(cp->soc->mmu);
	} else {
		DEBUG(LOG("READ -- Control Register"));
	}

	return(data);
}

static void _csx_cp15_creg_alloc(csx_coprocessor_p cp)
{
	csx_cp15_reg1_p cr1 = &cp->cp15_reg1;

	const uint32_t set = _CP15_reg1_bit(r);

	cr1->on_reset.clear = ~0U;
	cr1->on_reset.set = set;

	/* **** */

	const uint32_t ivc = _CP15_reg1_bit(a)
		| _CP15_reg1_bit(b)
		| _CP15_reg1_bit(r)
		| _CP15_reg1_bit(l4)
		| _CP15_reg1_bit(m)
		| _CP15_reg1_bit(v)
		| _CP15_reg1_bit(ve);

	const uint32_t ivs = _CP15_reg1_bit(dt)
		| _CP15_reg1_bit(it);

	cr1->invalid.clear = ~0U & ~(ivc | ivs | set);
	cr1->invalid.set = ivs;
}

uint32_t csx_coprocessor_access(csx_coprocessor_p cp, uint32_t* write)
{
	const soc_core_p core = cp->core;
//	const csx_p csx = cp->csx;

	if(15 == ir_cp_num(IR)) {
		const csx_coprocessor_access_p cpar = _csx_coprocessor_access(cp, IR);

		if(cpar->fn)
			return(cpar->fn(cpar->param, write));
	}

	LOG("P:%02u, 1:%01u, N:%02u, M:%02u, 2:%01u",
		ir_cp_num(IR), ir_cp_op1(IR), ir_cp_crn(IR), ir_cp_crm(IR), ir_cp_op2(IR));

	soc_core_disasm(core, IP, IR);
	LOG_ACTION(exit(-1));

	return(0);
}

csx_coprocessor_p csx_coprocessor_alloc(csx_p csx, csx_coprocessor_h h2cp)
{
	ERR_NULL(csx);
	ERR_NULL(h2cp);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	const csx_coprocessor_p cp = handle_calloc((void*)h2cp, 1, sizeof(csx_coprocessor_t));
	ERR_NULL(cp);

	cp->csx = csx;

	/* **** */

	csx_callback_atexit(csx, &cp->atexit, __csx_coprocessor_atexit, h2cp);
	csx_callback_atreset(csx, &cp->atreset, __csx_coprocessor_atreset, cp);

	/* **** */

	_csx_cp15_creg_alloc(cp);

	return(cp);
}

void csx_coprocessor_init(csx_coprocessor_p cp)
{
	ERR_NULL(cp);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	cp->soc = cp->csx->soc;
	ERR_NULL(cp->soc);

	cp->core = cp->soc->core;
	ERR_NULL(cp->core);

	/* **** */

	csx_coprocessor_register_access(cp, cp15(0, 1, 0, 0),
		_csx_cp15_0_1_0_0_access, cp);
}

void csx_coprocessor_register_access(csx_coprocessor_p cp,
	uint32_t cpx, coprocessor_access_fn fn, void* param)
{
	if(15 == ir_cp_num(cpx)) {
		const csx_coprocessor_access_p cpar = _csx_coprocessor_access(cp, cpx);

		cpar->fn = fn;
		cpar->param = param;
	}
}
