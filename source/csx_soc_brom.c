#include "csx_soc_brom.h"

/* **** */

#include "csx_soc.h"
#include "csx.h"

/* **** */

#include "libbse/include/err_test.h"
#include "libbse/include/log.h"

/* **** */

#include <inttypes.h>
#include <stdint.h>

/* **** */

typedef struct cc_t* cc_p;
typedef struct cc_t {
	uint32_t cs, ip, pc;
	uint32_t ds, dp;
//
	void* sdp, *p2cs, *p2ds;
}cc_t;

/* **** */

static void cc_org(cc_p p2cc, const uint32_t cs)
{
	p2cc->cs = cs;

	p2cc->p2cs = p2cc->sdp + cs;
	p2cc->pc = 0;

	if(0) LOG("sdp: 0x%016" PRIxPTR ", p2cs: 0x%016" PRIxPTR,
		(uintptr_t)p2cc->sdp, (uintptr_t)p2cc->p2cs);
}

static void cc_org_data(cc_p p2cc, const uint32_t ds)
{
	p2cc->ds = ds;

	p2cc->p2ds = p2cc->sdp + ds;
	p2cc->dp = 0;

	if(0) LOG("sdp: 0x%016" PRIxPTR ", p2ds: 0x%016" PRIxPTR,
		(uintptr_t)p2cc->sdp, (uintptr_t)p2cc->p2ds);
}

static cc_p cc_start(void *const sdp, const uint32_t cs, const uint32_t ds)
{
	static cc_t cc;

	cc.sdp = sdp;

	cc_org(&cc, cs);
	cc_org_data(&cc, ds);

	return(&cc);
}

static uint32_t cc(cc_p p2cc, const uint32_t ir)
{
	p2cc->ip = p2cc->pc;
	p2cc->pc += 4;

	const uint32_t cs_ip = p2cc->cs + p2cc->ip;
	const uint32_t cs_pc = p2cc->cs + p2cc->pc;

	if(0) {
		LOG_START("(cs: 0x%08x, ip: 0x%08x): 0x%08x", p2cc->cs, p2cc->ip, cs_ip);
		_LOG_(", pc: 0x%08x", p2cc->pc);
		_LOG_(", (cs + pc): 0x%08x", cs_pc);
		LOG_END(", ir: 0x%08x", ir);
	}

	uint32_t* p = p2cc->p2cs + (p2cc->ip & 0xffff);
	*p = ir;

	return(cs_pc);
}

static uint32_t cc_dw(cc_p p2cc, const uint32_t data)
{
	const uint32_t dp = p2cc->dp;
	p2cc->dp += 4;

	const uint32_t ds_dp = p2cc->ds + dp;

	if(0) {
		LOG_START("(ds: 0x%08x, dp: 0x%08x): 0x%08x", p2cc->ds, dp, ds_dp);
		LOG_END(", data: 0x%08x", data);
	}

	uint32_t* p = p2cc->p2ds + (dp & 0xffff);
	*p = data;

	return(ds_dp);
}

static uint32_t _arm_ir_rd(const unsigned rd)
{ return(pbBFMOV(rd, 0, 4, 12)); }

static uint32_t _arm_ir_rn(const unsigned rn)
{ return(pbBFMOV(rn, 0, 4, 16)); }

static uint32_t arm_b(cc_p p2cc, const uint32_t pat)
{
	const uint32_t cs_pc = p2cc->cs + p2cc->pc;

	if(0) LOG("(cs: 0x%08x, pc: 0x%08x): 0x%08x", p2cc->cs, p2cc->pc, cs_pc);

	const uint32_t offset = ((-8 + (pat - cs_pc)) >> 2);
	const uint32_t offset_masked = offset & 0x00ffffff;

	if(0) {
		LOG_START("offset: 0x%08x", offset);
		LOG_END(", offset_masked: 0x%08x", offset_masked);
	}

	assert(offset == offset_masked);

	const uint32_t ir = 0xea000000
		+ offset;

	return(cc(p2cc, ir));
}

static uint32_t arm_ldr(cc_p p2cc, const unsigned rd, const unsigned rn, const uint32_t pat)
{
	if(0) {
		LOG_START("rd: %u", rd);
		_LOG_(", rn: %u", rn);
		LOG_END(", pat: 0x%08x", pat);
	}

	const uint32_t cs_pc = p2cc->cs + p2cc->pc;

	if(0) LOG("(cs: 0x%08x, pc: 0x%08x): 0x%08x", p2cc->cs, p2cc->pc, cs_pc);

//	const uint32_t offset = ((-8 + (pat - cs_pc)) >> 2);
	const uint32_t offset = -8 + (pat - cs_pc);
	const uint32_t offset_masked = offset & 0x00000fff;

	if(0) {
		LOG_START("offset: 0x%08x", offset);
		LOG_END(", offset_masked: 0x%08x", offset_masked);
	}

	assert(offset == offset_masked);

	const uint32_t ir = 0xe5900000
		+ _arm_ir_rd(rd)
		+ _arm_ir_rn(rn);

	return(cc(p2cc, ir + offset));
}

enum {
	r0, r1, r2, r3, r4, r5, r6, r7,
	r8, r9, r10, r11, r12, r13, r14, r15,
//
	rLR = r14,
	rPC = r15,
	rSP = r13,
};

void csx_soc_brom_init(csx_soc_p const soc, csx_data_p const cdp)
{
	ERR_NULL(soc);
	ERR_NULL(cdp);

	cc_p cc = cc_start(soc->brom, 0x00000000, 0x00001000);
	const uint32_t base_dw = cc_dw(cc, cdp->base);
	const uint32_t sp_dw = cc_dw(cc, SOC_SRAM_END);

	arm_b(cc, 0x100);

	cc_org(cc, 0x100);
	arm_ldr(cc, rSP, rPC, sp_dw);
	arm_ldr(cc, rPC, rPC, base_dw);
}
