#pragma once

/* **** */

//#include "../../../include/queue.h"
#include "queue.h"

/* **** */

#include <stdint.h>

/* **** */

enum {
	rrRD,
	rrRM,
	rrRN,
	rrRS,
	rrRSOP,
	rrRSCO,
	REG_COUNT,

	rrPTR = 0x10,
};

enum {
	rSP = 13,
	rLR,
	rPC,
};

/* **** */

enum {
	SYMBOL_DATA,
	SYMBOL_TEXT,
};

typedef struct symbol_t** symbol_h;
typedef struct symbol_t* symbol_p;
typedef struct symbol_t {
	qelem_t qelem;

//	uint32_t end_pat;
	uint flags;
	uint pass;
	uint32_t pat;
	uint refs;
	struct {
		uint dst;
		uint src;
	}reg;
	size_t size;
	uint type;
}symbol_t;

typedef struct cracker_t* cracker_p;
typedef struct cracker_t {
	uint32_t ip;
#define IP cj->ip

	uint32_t ir;
#define IR cj->ir

	struct {
		uint32_t v;
		uint8_t src:4;
		uint8_t isPtr:1;
	}reg[16];
#define GPR(_x) cj->reg[_x]
#define vGPR(_x) GPR(_x).v

	uint32_t vr[REG_COUNT];
#define vRx(_x) cj->vr[_x]
#define vR(_x) vRx(rrR##_x)

	uint8_t cc; /* for thumb */
#define CCv cj->cc
#define CCx ((IP & 1) ? CCv : ARM_IR_CC)

	uint8_t rr[REG_COUNT];
#define rRx(_x) cj->rr[_x]
#define rR(_x) rRx(rrR##_x)

	struct {
		uint32_t base;
		void* data;
		uint32_t end;
		size_t size;
	}content;

	symbol_p symbol;
	uint symbol_pass;
	symbol_p symbol_qhead;
}cracker_t;

#define IS_THUMB (IP & 1)

#define vGPR_rR(_x) vGPR(rR(_x))
#define vGPR_rRx(_x) vGPR(rRx(_x))

#define vRx_GPR(_x) (rPC == (_x) ? (IS_THUMB ? THUMB_PC : ARM_PC) : vGPR(_x))
#define vR_GPR(_x) vRx_GPR(rR(_x))
#define rR_NAME(_x) reg_name[rR(_x)]

#define rR_SRC(_x) GPR(rR(_x)).src

#define LR vGPR(rLR)
#define PC vGPR(rPC)

#define ARM_PC (4 + (PC & ~3))
#define THUMB_PC (2 + (PC & ~1))

/* **** */

uint32_t _read(cracker_p cj, uint32_t pat, uint8_t size);
symbol_p cracker_data(cracker_p cj, uint32_t pat, size_t size);
void cracker_reg_dst(cracker_p cj, uint8_t r);
void cracker_reg_src(cracker_p cj, uint8_t r);
symbol_p cracker_text(cracker_p cj, uint32_t pat);

/* **** */

#define setup_rR_vR(_r, _rr, _vr) _setup_rR_vR(cj, rrR##_r, _rr, _vr)
static inline void _setup_rR_vR(cracker_p cj, uint8_t rx, uint8_t rr, uint32_t vr) {
	rRx(rx) = rr;
	vRx(rx) = vr;
}

#define setup_rR_dst(_rxd, _rrd) _setup_rR_dst(cj, rrR##_rxd, _rrd)
static inline void _setup_rR_dst(cracker_p cj, uint8_t rxd, uint8_t rrd)
{
	_setup_rR_vR(cj, rxd, rrd, 0);

	cracker_reg_dst(cj, rrd);
	
	GPR(rrd).src = 0;
	GPR(rrd).isPtr = 0;
}

#define setup_rR_dst_src(_rxd, _rrd, _rrs) _setup_rR_dst_src(cj, rrR##_rxd, _rrd, _rrs)
static inline void _setup_rR_dst_src(cracker_p cj, uint8_t rxd, uint8_t rrd, uint8_t rrs)
{
	_setup_rR_dst(cj, rxd, rrd);

	GPR(rrd).src = rrs;
}

#define setup_rR_vR_dst_src(_rxd, _rrd, _rrs) _setup_rR_vR_dst_src(cj, rrR##_rxd, _rrd, _rrs)
static inline void _setup_rR_vR_dst_src(cracker_p cj, uint8_t rxd, uint8_t rrd, uint8_t rrs)
{
	_setup_rR_dst_src(cj, rxd, rrd, rrs);

	vRx(rxd) = vRx_GPR(rrs);
}

#define setup_rR_src(_rxs, _rrs) _setup_rR_src(cj, rrR##_rxs, _rrs)
static inline void _setup_rR_src(cracker_p cj, uint8_t rxs, uint8_t rrs)
{
	_setup_rR_vR(cj, rxs, rrs, 0);

	cracker_reg_src(cj, rrs);
}

#define setup_rR_vR_src(_rxs, _rrs) _setup_rR_vR_src(cj, rrR##_rxs, _rrs)
static inline void _setup_rR_vR_src(cracker_p cj, uint8_t rxs, uint8_t rrs)
{
	_setup_rR_src(cj, rxs, rrs);

	vRx(rxs) = vRx_GPR(rrs);
}
