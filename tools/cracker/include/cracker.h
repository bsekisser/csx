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
	REG_COUNT,
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

	uint flags;
	uint pass;
	uint32_t pat;
	uint refs;
	size_t size;
	uint type;
}symbol_t;

typedef struct cracker_t* cracker_p;
typedef struct cracker_t {
	uint32_t ip;
#define IP cj->ip

	uint32_t ir;
#define IR cj->ir

	uint32_t reg[16];
	uint8_t reg_src[16];
#define GPR(_x) cj->reg[_x]
#define GPR_SRC(_x) cj->reg_src[_x]
	
	uint32_t vr[REG_COUNT];
#define vR(_x) cj->vr[rrR##_x]

	uint8_t cc; /* for thumb */
#define CCv cj->cc
#define CCx ((IP & 1) ? CCv : ARM_IR_CC)

	uint8_t rr[REG_COUNT];
#define rR(_x) cj->rr[rrR##_x]

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

#define rR_GPR(_x) GPR(rR(_x))
#define vR_GPR(_x) (rPC == rR(_x) ? (IS_THUMB ? THUMB_PC : ARM_PC) : rR_GPR(_x))
#define rR_NAME(_x) reg_name[rR(_x)]
#define rR_SRC(_x) GPR_SRC(rR(_x))
#define xR_SRC(_x) ((uint8_t)~rR_SRC(_x))

#define LR GPR(rLR)
#define PC GPR(rPC)

#define ARM_PC (4 + (PC & ~3))
#define THUMB_PC (2 + (PC & ~1))

/* **** */

#define setup_rR_vR(_r, _rr, _vr) \
	({ \
		rR(_r) = _rr; \
		vR(_r) = _vr; \
	})

/* **** */

uint32_t _read(cracker_p cj, uint32_t pat, uint8_t size);
symbol_p cracker_data(cracker_p cj, uint32_t pat, size_t size);
symbol_p cracker_text(cracker_p cj, uint32_t pat);
