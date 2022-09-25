#include "bitfield.h"
#include "err_test.h"
#include "log.h"
#include "shift_roll.h"

/* **** */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* **** */

//#define RGNDirPath "../../../garmin/rgn_files/"
#define RGNDirPath "../../../garmin/rgn_files/"

//#define RGNFileName "029201000350" /* xxx */

#define RGNFileName "038201000610"
//#define RGNFileName "038201000280"

//#define RGNFileName "048101000610"

//#define RGNFileName "049701000610"

/* **** */

#define ARM_DPI_OP mlBFEXT(IR, 24, 21)
#define ARM_DPI_I BEXT(IR, 25)
#define ARM_DPI_S BEXT(IR, 20)
#define ARM_DPI_SOP mlBFEXT(IR, 6, 5)

#define ARM_IR_RD mlBFEXT(IR, 15, 12)
#define ARM_IR_RM mlBFEXT(IR, 3, 0)
#define ARM_IR_RN mlBFEXT(IR, 19, 16)
#define ARM_IR_RS mlBFEXT(IR, 11, 8)

#define ARM_LDST_B BEXT(IR, 22)
#define ARM_LDST_H BEXT(IR, 5)
#define ARM_LDST_I22 BEXT(IR, 22)
#define ARM_LDST_L BEXT(IR, 20)
#define ARM_LDST_P BEXT(IR, 24)
#define ARM_LDST_U BEXT(IR, 23)
#define ARM_LDST_S BEXT(IR, 6)
#define ARM_LDST_W BEXT(IR, 21)
#define ARM_LDSTM_S BEXT(IR, 22)

#define ARM_LDST_FLAG_B (ARM_LDST_FLAG_S && !ARM_LDST_H)
#define ARM_LDST_FLAG_H (ARM_LDST_H & !ARM_LDST_FLAG_D)
#define ARM_LDST_FLAG_D (!ARM_LDST_L && ARM_LDST_S)
#define ARM_LDST_FLAG_S (ARM_LDST_L && ARM_LDST_S)

#define CCs(_x) _condition_code_string[_x][CCx]

#define _CORE_TRACE_(_f, ...) \
		printf(_f, ##__VA_ARGS__);

#define CORE_TRACE(_f, ...) \
	({ \
		CORE_TRACE_START(); \
		CORE_TRACE_END(_f, ##__VA_ARGS__); \
	})

#define CORE_TRACE_START(_f, ...) \
	_CORE_TRACE_("%c(0x%08x, 0x%08x: " _f, (uint)IP & 1 ? 'T' : 'A', (uint)IP & ~1, IR, ##__VA_ARGS__);

#define CORE_TRACE_END(_f, ...) \
	_CORE_TRACE_(_f ");\n", ##__VA_ARGS__);

#define setup_rR_vR(_r, _rr, _vr) \
	({ \
		rR(_r) = _rr; \
		vR(_r) = _vr; \
	})
	
/* **** */

enum {
	rrRD,
	rrRM,
	rrRN,
	rrRS,
	REG_COUNT,
};

typedef struct cracker_t* cracker_p;
typedef struct cracker_t {
	uint32_t ip;
#define IP cj->ip

	uint32_t ir;
#define IR cj->ir

	uint32_t pc;
#define PC cj->pc

	uint32_t vr[REG_COUNT];
#define vR(_x) cj->vr[rrR##_x]

	uint8_t cc;
#define CCx cj->cc

	uint8_t rr[REG_COUNT];
#define rR(_x) cj->rr[rrR##_x]

	void* content;
	uint32_t content_base;
	size_t content_size;
}cracker_t;

/* **** */

enum {
	rSP = 13,
	rLR = 14,
	rPC = 15,
};

enum {
	SOP_LSL, SOP_LSR, SOP_ASR, SOP_ROR,
};

enum {
	ARM_AND, ARM_EOR, ARM_SUB, ARM_RSB,
	ARM_ADD, ARM_ADC, ARM_SBC, ARM_RSC,
	ARM_TST, ARM_TEQ, ARM_CMP, ARM_CMN,
	ARM_ORR, ARM_MOV, ARM_BIC, ARM_MVN,
};

/* **** */

const char* arm_reg_name[16] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "SP", "LR", "PC",
};

static const char* _condition_code_string[2][16] = {
	{ "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT", "GT", "LE", "", "" },
	{ "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV" },
};

const char* dpi_op_string[16] = {
	"AND", "EOR", "SUB", "RSB", "ADD", "ADC", "SBC", "RSC",
	"TST", "TEQ", "CMP", "CMN", "ORR", "MOV", "BIC", "MVN",
};

const char* shift_op_string[6] = {
	"LSL", "LSR", "ASR", "ROR"
};

/* **** */

static uint32_t _read(cracker_p cj, uint32_t pat, uint8_t size)
{
	uint32_t res = 0;
	uint8_t* src = 0;

	uint content_end = cj->content_base + cj->content_size;

	if((pat >= cj->content_base) && ((pat + size) <= content_end))
		src = cj->content + (pat - cj->content_base);
	else
		return(0xdeadbeef);

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

/* **** */

static int arm_b_bl(cracker_p cj)
{
	int link = BEXT(IR, 24);
	int32_t offset = mlBFEXTs(IR, 23, 0) << 2;

	uint32_t new_pc = (IP + 8) + offset;

	CORE_TRACE("B%s%s(0x%08x)", link ? "L" : "", CCs(0), new_pc);
	
	if(0xe == CCx)
		PC = new_pc;

	return(1);
}

static int arm_bxt(cracker_p cj)
{
	assert(0xf == mlBFEXT(IR, 19, 16));
	assert(0xf == mlBFEXT(IR, 15, 12));
	assert(0xf == mlBFEXT(IR, 11, 8));

	CORE_TRACE("BX%s(%s)", CCs(0), arm_reg_name[ARM_IR_RM]);
	
	return(0);
}

static void arm_dpi(cracker_p cj)
{
	CORE_TRACE_START();

	switch(ARM_DPI_OP) {
		case ARM_ADC:
		case ARM_ADD:
		case ARM_AND:
		case ARM_BIC:
		case ARM_EOR:
		case ARM_ORR:
		case ARM_RSB:
		case ARM_RSC:
		case ARM_SBC:
		case ARM_SUB:
			_CORE_TRACE_("%s%s%s(%s, %s, ",
				dpi_op_string[ARM_DPI_OP], CCs(0), ARM_DPI_S ? "S" : "",
				arm_reg_name[ARM_IR_RD], arm_reg_name[ARM_IR_RN]);
			break;
		case ARM_CMP:
		case ARM_CMN:
		case ARM_TEQ:
		case ARM_TST:
			_CORE_TRACE_("%s%s(%s, ",
				dpi_op_string[ARM_DPI_OP], CCs(0),
				arm_reg_name[ARM_IR_RN]);
			break;
		case ARM_MOV:
		case ARM_MVN:
			assert(0 == mlBFEXT(IR, 19, 16));
			_CORE_TRACE_("%s%s%s(%s, ",
				dpi_op_string[ARM_DPI_OP], CCs(0), ARM_DPI_S ? "S" : "",
				arm_reg_name[ARM_IR_RD]);
			break;
		default:
			CORE_TRACE_END("0x%02x, %s", ARM_DPI_OP, dpi_op_string[ARM_DPI_OP]);
			LOG_ACTION(exit(-1));
			break;
	}
}

static int arm_dpi_i(cracker_p cj)
{
	uint shift = mlBFEXT(IR, 11, 8);
	uint imm8 = mlBFEXT(IR, 7, 0);

	arm_dpi(cj);

	if(shift) {
		CORE_TRACE_END("ROR(0x%02x, 0x%02x); /* 0x%08x */", imm8, shift, _ror(imm8, shift));
	} else {
		CORE_TRACE_END("0x%02x)", imm8);
	}
	
	return(rPC != ARM_IR_RD);
}

static int arm_dpi_rs(cracker_p cj) {
	arm_dpi(cj);
	
	setup_rR_vR(M, ARM_IR_RM, 0);
	setup_rR_vR(S, ARM_IR_RS, 0);
	
	CORE_TRACE_END("%s(%s, %s))",
		shift_op_string[ARM_DPI_SOP],
		arm_reg_name[rR(M)], arm_reg_name[rR(S)]);
	
	return(rPC != ARM_IR_RD);
}

static int arm_dpi_s(cracker_p cj) {
	uint shift = mlBFEXT(IR, 11, 7);

	switch(ARM_DPI_SOP) {
		case SOP_ASR:
		case SOP_LSR:
			if(0 == shift)
				shift = 32;
			break;
	}

	rR(M) = mlBFEXT(IR, 3, 0);
	
	arm_dpi(cj);
	
	if(shift) {
		CORE_TRACE_END("%s(%s, 0x%02x))",
			shift_op_string[ARM_DPI_SOP],
			arm_reg_name[rR(M)], shift);
	} else {
		if(SOP_ROR == ARM_DPI_SOP) {
			CORE_TRACE_END("RRX(%s))", arm_reg_name[rR(M)]);
		} else {
			CORE_TRACE_END("%s)", arm_reg_name[rR(M)]);
		}
	}
	
	return(rPC != ARM_IR_RD);
}


static uint32_t arm_fetch(cracker_p cj)
{
	PC += sizeof(uint32_t);
	
	return(_read(cj, IP, sizeof(uint32_t)));
}

static void arm_ldst(cracker_p cj)
{
	CORE_TRACE_START();
	
	/* ldr|str{cond}{b}{t} <rd>, <addressing_mode> */
	/* ldr|str{cond}{h|sh|sb|d} <rd>, <addressing_mode> */

	int ldst_t = !ARM_LDST_P && ARM_LDST_W;

	switch(mlBFEXT(IR, 27, 25)) {
		case 0x00: { /* miscellaneous load/store */
			int ldst_l = ARM_LDST_L || (!ARM_LDST_L && ARM_LDST_H);
			
			_CORE_TRACE_("%sR%s", ldst_l ? "LD" : "ST", CCs(0));
			_CORE_TRACE_("%s", ARM_LDST_FLAG_S ? "S" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_H ? "H" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_B ? "B" : "");
			_CORE_TRACE_("%s", ARM_LDST_FLAG_D ? "D" : "");
		}break;
		case 0x02: { /* default load store */
			_CORE_TRACE_("%sR%s", ARM_LDST_L ? "LD" : "ST", CCs(0));
			_CORE_TRACE_("%s%s", ARM_LDST_B ? "B" : "", ldst_t ? "T" : "");
		}break;
	}

	_CORE_TRACE_("(%s, ", arm_reg_name[ARM_IR_RD]);
}

static int arm_ldst_i(cracker_p cj)
{
	arm_ldst(cj);
	
	int32_t offset = mlBFEXT(IR, 11, 0);
	
	int wb = !ARM_LDST_P || (ARM_LDST_P && ARM_LDST_W);
	
	_CORE_TRACE_("%s%s, %s0x%04x",
		arm_reg_name[ARM_IR_RN],
		wb ? " | rWB" : "", ARM_LDST_U ? "" : "-", offset);
	
	_CORE_TRACE_(")");

	if(rPC == ARM_IR_RN) {
		if(!ARM_LDST_U)
			offset = ~offset;

		uint32_t pat = (IP + 8) + offset;
		size_t size = ARM_LDST_B ? sizeof(uint8_t) : sizeof(uint32_t);

		uint32_t data = _read(cj, pat, size);

		if(ARM_LDST_B) {
			_CORE_TRACE_("; /* 0x%02x */", data);
		} else {
			_CORE_TRACE_("; /* 0x%08x */", data);
		}
	}

	CORE_TRACE_END();
	
	return(rPC != ARM_IR_RD);
}

static int arm_ldst_sh(cracker_p cj)
{
	arm_ldst(cj);
	
	int wb = !ARM_LDST_P || (ARM_LDST_P && ARM_LDST_W);

	if(ARM_LDST_I22) {
		uint8_t offset = mlBFMOV(IR, 11, 8, 4) | mlBFEXT(IR, 3, 0);

		_CORE_TRACE_("%s%s, %s0x%04x",
			arm_reg_name[ARM_IR_RN],
			wb ? " | rWB" : "", ARM_LDST_U ? "" : "-", offset);
	} else {
		assert(0 == mlBFEXT(IR, 11, 8));
		
		_CORE_TRACE_("%s%s, %s%s",
			arm_reg_name[ARM_IR_RN],
			wb ? " | rWB" : "", ARM_LDST_U ? "" : "-", arm_reg_name[ARM_IR_RM]);
		
	}
	
	CORE_TRACE_END(")");
	
	return(rPC != ARM_IR_RD);
}

static int arm_ldstm(cracker_p cj)
{
	CORE_TRACE_START("%sM%s", ARM_LDST_L ? "LD" : "ST", CCs(0));
	_CORE_TRACE_("%c%c", ARM_LDST_U ? 'I' : 'D', ARM_LDST_P ? 'B' : 'A');
	_CORE_TRACE_("(%s%s, ", arm_reg_name[ARM_IR_RN], ARM_LDST_W ? ".WB" : "");
	
	char reglist[17], *dst = reglist;
	
	for(int i = 0; i < 16; i++) {
		if(BEXT(IR, i))
			*dst++ = (i < 9 ? '0' : ('a' - 9)) + i;
		else
			*dst++ = '.';
	}

	*dst = 0;

	CORE_TRACE_END("{%s}%s)", reglist, ARM_LDSTM_S ? ".S" : "");
	
	return(0xe == CCx || !BEXT(IR, rPC));
}

static int arm_mcr_mrc(cracker_p cj)
{
	int is_mrc = BEXT(IR, 20);

	CORE_TRACE_START();
	
	_CORE_TRACE_("M%s%s(CP%u, %u, %s, CRn(%u), CRm(%u)",
		is_mrc ? "CR" : "RC", CCs(0),
		mlBFEXT(IR, 11, 8), mlBFEXT(IR, 23, 21),
		arm_reg_name[ARM_IR_RD],
		mlBFEXT(IR, 19, 16), mlBFEXT(IR, 3, 0));
	
	uint op2 = mlBFEXT(IR, 7, 5);

	if(op2) {
		_CORE_TRACE_(", %u)", op2);
	}
	
	CORE_TRACE_END();
	
	return(rPC != ARM_IR_RD);
}

static int arm_mrs(cracker_p cj)
{
	assert(0xf == mlBFEXT(IR, 19, 16));
	assert(0 == mlBFEXT(IR, 11, 0));

	int bit_r = BEXT(IR, 22);

	CORE_TRACE("MRS%s(%s, %cPSR)",
		CCs(0),
		arm_reg_name[ARM_IR_RD], bit_r ? 'S' : 'C');

	return(1);
}

static int arm_msr(cracker_p cj)
{
	assert(0x0f == mlBFEXT(IR, 15, 12));

	CORE_TRACE_START();

	int bit_r = BEXT(IR, 22);

	const char psr_fields[5] = {
		BEXT(IR, 16) ? 'C' : 'c',
		BEXT(IR, 17) ? 'X' : 'x',
		BEXT(IR, 18) ? 'S' : 's',
		BEXT(IR, 19) ? 'F' : 'f',
		0,
	};

	if(BEXT(IR, 25)) {
		_CORE_TRACE_("MSR%s(%cPSR_%s, ",
			CCs(0),
			bit_r ? 'S' : 'C',
			psr_fields);

		uint imm8 = mlBFEXT(IR, 7, 0);
		uint shift = mlBFEXT(IR, 11, 8) << 1;
		
		if(shift) {
			_CORE_TRACE_("ROR(%02u, %03u)", shift, imm8);
		} else {
			_CORE_TRACE_("%03u", imm8);
		}
		
	} else {
		
		if(0 != mlBFEXT(IR, 11, 8)) {
			CORE_TRACE_END();
			LOG_ACTION(exit(-1));
		}

		_CORE_TRACE_("MSR%s(%cPSR_%s, %s",
			CCs(0),
			bit_r ? 'S' : 'C',
			psr_fields,
			arm_reg_name[ARM_IR_RM]);
	}

	CORE_TRACE_END(")");

	return(1);
}

/* **** */

const uint32_t _arm_inst0_0_i74 = _BV(7) | _BV(4);
const uint32_t _arm_inst0_0_misc = _BV(24);
const uint32_t _arm_inst0_0_misc_mask = mlBF(27, 23) | _BV(20);

const uint32_t _arm_inst0_1_bxt = _BV(24) | _BV(21) | _BV(4);
const uint32_t _arm_inst0_1_mask = (mlBF(27, 20) & (~_BV(22))) | mlBF(7, 4);
const uint32_t _arm_inst0_1_mrs = _BV(24);
const uint32_t _arm_inst0_1_msr = _BV(24) | _BV(21);

const uint32_t _arm_inst1_mask = mlBF(27, 20) & (~_BV(22));
const uint32_t _arm_inst1_mi2sr = mlBF(25, 24) | _BV(21);
const uint32_t _arm_inst1_undefined = mlBF(25, 24);

//const uint32_t _arm_inst7_cdp = mlBF(27, 25);
const uint32_t _arm_inst7_mcr_mrc = mlBF(27, 25) | _BV(4);
const uint32_t _arm_inst7_mask = mlBF(27, 24) | _BV(4);

static int arm_step(cracker_p cj)
{
	IR = arm_fetch(cj);
	CCx = mlBFEXT(IR, 31, 28);

	uint ir_27_25 = mlBFEXT(IR, 27, 25);

	if(0xf != CCx) switch(ir_27_25) {
		case 0x00:
			if(_arm_inst0_0_i74 == (IR & _arm_inst0_0_i74)) {
				if(0 != mlBFEXT(IR, 6, 5))
					return(arm_ldst_sh(cj));
			} else if(_arm_inst0_0_misc != (IR & _arm_inst0_0_misc_mask)) {
				if(BEXT(IR, 4))
					return(arm_dpi_rs(cj));
				else
					return(arm_dpi_s(cj));
			} else {
				switch(IR & _arm_inst0_1_mask) {
					case _arm_inst0_1_bxt:
						return(arm_bxt(cj));
						break;
					case _arm_inst0_1_mrs:
						return(arm_mrs(cj));
						break;
					case _arm_inst0_1_msr:
						return(arm_msr(cj));
						break;
					default:
						CORE_TRACE("0x%08x", IR & _arm_inst0_1_mask);
						LOG_ACTION(exit(-1));
						break;
				}
			}break;
		case 0x01:
			if(_arm_inst1_mi2sr == (IR & _arm_inst1_mask))
				return(arm_msr(cj));
			else if(_arm_inst1_undefined != (IR & _arm_inst1_mask))
				return(arm_dpi_i(cj));
			break;
		case 0x02:
			return(arm_ldst_i(cj));
			break;
		case 0x04:
			return(arm_ldstm(cj));
			break;
		case 0x05:
			return(arm_b_bl(cj));
			break;
		case 0x07:
			if(_arm_inst7_mcr_mrc == (IR & _arm_inst7_mask))
				return(arm_mcr_mrc(cj));
			break;
	}
	
	CORE_TRACE_START("IR[27, 25] = 0x%02x", ir_27_25)

	switch(ir_27_25) {
		case 0x00:
		case 0x01:
			_CORE_TRACE_("DPI_OP = 0x%02x (%s), IR[7] = %0u, IR[4] = %0u",
				ARM_DPI_OP, dpi_op_string[ARM_DPI_OP], BEXT(IR, 7), BEXT(IR, 4));
			break;
		case 0x07:
			_CORE_TRACE_("IR[27:24] = 0x%02x, IR[4] = %u", mlBFEXT(IR, 27, 24), BEXT(IR, 4));
			break;
		default:
			break;
	}

	CORE_TRACE_END();

	return(0);
}

static int step(cracker_p cj)
{
	IP = PC;

	if(IP & 1)
;//		return(thumb_step(cj));

	return(arm_step(cj));
}

/* **** */

int main(void)
{
	int fd;
	ERR(fd = open(RGNDirPath RGNFileName "_loader.bin", O_RDONLY));

	struct stat sb;

	ERR(fstat(fd, &sb));
	
	void *data;
	ERR_NULL(data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));

	close(fd);
	
	cracker_t cjt, *cj = &cjt;
	
	cjt.content = data;
	cjt.content_base = 0x10020000;
	cjt.content_size = sb.st_size;
	cjt.pc = cjt.content_base;
	
	while(step(&cjt))
		;

	CORE_TRACE();

	munmap(data, sb.st_size);
}
