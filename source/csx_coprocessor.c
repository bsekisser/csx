#include "config.h"

#include "soc_core_cp15.h"
#include "soc_core_disasm.h"
#include "soc_core.h"

#include "csx_coprocessor.h"
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

typedef struct csx_coprocessor_t {
	csx_coprocessor_access_t cp15[16][16][7][7];
	soc_core_p core;
	csx_p csx;
	csx_soc_p soc;

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}csx_coprocessor_t;

/* **** */

csx_coprocessor_access_p _csx_coprocessor_access(csx_coprocessor_p cp, uint32_t ir)
{
	return(&cp->cp15[ir_cp_crn(ir)][ir_cp_crm(ir)][ir_cp_op1(ir)][ir_cp_op2(ir)]);
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

//	const csx_coprocessor_h h2cp = param;
//	csx_coprocessor_p cp = *h2cp;

	return(0);
	UNUSED(param);
}

/* **** */

uint32_t _csx_cp15_x_x_x_x_access(void* param, uint32_t* write)
{
	const soc_core_p core = param;

	return(soc_core_cp15(core, write));
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
	if(0) csx_callback_atreset(csx, &cp->atreset, __csx_coprocessor_atreset, cp);

	/* **** */

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
		_csx_cp15_x_x_x_x_access, cp->core);
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
