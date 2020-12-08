#include "csx.h"

/* **** */

#if 1
	#define T(_x) _x
	#define ITRACE(_f, args...) \
		printf("I(0x%08x, %s, /* %c 0x%08x */ " _f ")\n", \
			csx->pc, csx->ccs, cce ? '>' : '|', opcode, ## args);
	#define TRACE(_f, args...) \
		printf("//0x%08x: " _f "\n", csx->pc, ## args);
#else
	#define T(_x) 0
	#define ITRACE(_f, args...)
	#define TRACE(_f, args...)
#endif

/* **** */

#include "csx_core_reg.h"
#include "csx_core_utility.h"

#include "csx_core_decode.h"

/* **** */

void csx_trace_inst_dpi(csx_p csx, uint32_t opcode, csx_dpi_p dpi, uint8_t cce)
{
	switch(dpi->type)
	{
		case DPI_IMMEDIATE:
			if(!dpi->shift)
			{
				if(!(dpi->rn & 0x0f))
				{
					ITRACE("%s%s(r[%u], r[%u], %u) %s",
						dpi->mnemonic, dpi->bit.s ? "s" : "",
						dpi->rd, dpi->rn, dpi->imm, dpi->op_string);
				}
				else
				{
					ITRACE("%s%s(r[%u], %u) %s",
						dpi->mnemonic, dpi->bit.s ? "s" : "",
						dpi->rd, dpi->imm, dpi->op_string);
				}
			}
			else
			{
				ITRACE("%s%s(r[%u], r[%u], %u, %u) %s",
					dpi->mnemonic, dpi->bit.s ? "s" : "",
					dpi->rd, dpi->rn, dpi->imm, dpi->shift, dpi->op_string);
			}
			break;
		case DPI_RM:
			ITRACE("%s%s(r[%u], r[%u]) %s",
				dpi->mnemonic, dpi->bit.s ? "s" : "",
				dpi->rd, dpi->rm, dpi->op_string);
			break;
		default:
			exit(0);
			break;
	}
}

static void csx_inst_dpi_final(csx_p csx, uint32_t opcode, csx_dpi_p dpi, uint8_t cce, uint8_t wb)
{
	csx_trace_inst_dpi(csx, opcode, dpi, cce);

	if(cce)
	{
		if(wb)
			csx_reg_set(csx, dpi->rd, dpi->rd_v);

		if(dpi->bit.s)
		{
			if(rPC == dpi->rd /* && PSR = CPSR*/)
			{
				exit(1);
			}
			else
			{
				csx->cpsr &= ~CSX_PSR_NZC;
				
				uint32_t rd_v = dpi->rd_v;
				uint32_t s1_v = dpi->rn_v;
				uint32_t s2_v = dpi->out.v;

				if(dpi->rd_v >> 31)
					csx->cpsr |= 1 << CSX_PSR_BIT_N;
				
				if(0 == dpi->rd_v)
					csx->cpsr |= 1 << CSX_PSR_BIT_Z;

				switch(dpi->flag_mode)
				{
					case CSX_CC_FLAGS_MODE_ADD:
					{
						csx->cpsr &= ~CSX_PSR_V;
						uint32_t xvec = (s1_v ^ s2_v);
						uint32_t ovec = (s1_v ^ rd_v) & ~xvec;
						
						if((1 << 31) & (xvec ^ ovec ^ rd_v))
							csx->cpsr |= 1 << CSX_PSR_BIT_C;
						if((1 << 31) & ovec)
							csx->cpsr |= 1 << CSX_PSR_BIT_V;

						if(1) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
							!!(csx->cpsr & CSX_PSR_N), !!(csx->cpsr & CSX_PSR_Z),
							!!(csx->cpsr & CSX_PSR_C), !!(csx->cpsr & CSX_PSR_V));

					}break;
					case CSX_CC_FLAGS_MODE_SUB:
					{
						csx->cpsr &= ~CSX_PSR_V;
						uint32_t xvec = (s1_v ^ s2_v);
						uint32_t ovec = (s1_v ^ rd_v) & ~xvec;
						
						if((1 << 31) & (xvec ^ ovec ^ rd_v))
							csx->cpsr |= 1 << CSX_PSR_BIT_C;
						if((1 << 31) & ovec)
							csx->cpsr |= 1 << CSX_PSR_BIT_V;
							
						if(1) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
							!!(csx->cpsr & CSX_PSR_N), !!(csx->cpsr & CSX_PSR_Z),
							!!(csx->cpsr & CSX_PSR_C), !!(csx->cpsr & CSX_PSR_V));
					}break;
					default:
					{
						if(dpi->out.c)
							csx->cpsr |= 1 << CSX_PSR_BIT_C;
					}break;
				}
			}
		}
	}
}

/* **** */

static void csx_inst_and(csx_p csx, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;
	
	csx_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_decode_shifter_operand(csx, opcode, &dpi);

	dpi.rn_v = csx_reg_get(csx, dpi.rn);
	dpi.rd_v = dpi.rn_v & dpi.out.v;

	dpi.mnemonic = "and";
	
	snprintf(dpi.op_string, 255,
		"/* 0x%08x & !0x%08x(0x%08x) --> 0x%08x */",
		dpi.rn_v, dpi.out.v, !dpi.out.v, dpi.rd_v);
	
	csx_inst_dpi_final(csx, opcode, &dpi, cce, 1);
}

#define CSX_INST_BIT_L_MASK (1 << 24)

static void csx_inst_b(csx_p csx, uint32_t opcode, uint8_t cce)
{
	uint8_t link = (0 != (opcode & CSX_INST_BIT_L_MASK));
	int32_t offset = _bits_sext(opcode, 23, 0);

	uint32_t pc = csx_reg_get(csx, rPC);

	uint32_t new_pc = pc + (offset << 2);
	
	ITRACE("b%s(0x%08x) /* 0x%08x */", link ? "l" : "", new_pc, offset);

	if(cce)
	{
		if(link)
			csx_reg_set(csx, rLR, pc);

		csx_reg_set(csx, rPC, new_pc);
	}
}

static void csx_inst_bic(csx_p csx, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;
	
	csx_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_decode_shifter_operand(csx, opcode, &dpi);

	dpi.rn_v = csx_reg_get(csx, dpi.rn);
	dpi.rd_v = dpi.rn_v & !dpi.out.v;

	dpi.mnemonic = "bic";
	
	snprintf(dpi.op_string, 255,
		"/* 0x%08x & !0x%08x(0x%08x) --> 0x%08x */",
		dpi.rn_v, dpi.out.v, !dpi.out.v, dpi.rd_v);
	
	csx_inst_dpi_final(csx, opcode, &dpi, cce, 1);
}

static void csx_inst_cmp(csx_p csx, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;
	
	csx_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_decode_shifter_operand(csx, opcode, &dpi);

	dpi.flag_mode = CSX_CC_FLAGS_MODE_SUB;

	dpi.rn_v = csx_reg_get(csx, dpi.rn);
	dpi.rd_v = dpi.rn_v - dpi.out.v;

	dpi.mnemonic = "cmp";
	
	snprintf(dpi.op_string, 255,
		"/* 0x%08x - 0x%08x(0x%08x) ??? 0x%08x */",
		dpi.rn_v, dpi.out.v, !dpi.out.v, dpi.rd_v);
	
	csx_inst_dpi_final(csx, opcode, &dpi, cce, 0);
}

static void csx_inst_ldst(csx_p csx, uint32_t opcode, uint8_t cce)
{
	uint16_t offset;
	csx_reg_t rn, rd;
	uint8_t ipubwl;

	csx_decode_ipubwl_rn_rd_offset(opcode, &ipubwl, &rd, &rn, &offset);

	uint32_t rn_v = csx_reg_get(csx, rn);
	uint32_t ea = rn_v + offset;

	if(ipubwl & 1) {
		uint32_t res = csx_mmu_read(csx, ea, sizeof(uint32_t));

		ITRACE("ldr(r[%u], r[%u], 0x%04x) /* 0x%08x: 0x%08x */",
				rd, rn, offset, ea, res);

		if(cce)
			csx_reg_set(csx, rd, res);
	}
	else
	{
		uint32_t res = csx_reg_get(csx, rd);
		
		ITRACE("str(r[%u], r[%u], 0x%04x) /* 0x%08x: 0x%08x */",
				rd, rn, offset, ea, res);

		if(cce)
			csx_mmu_write(csx, ea, res, sizeof(uint32_t));
	}
}

static void csx_inst_mov(csx_p csx, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;
	
	dpi.rn = -1;
	
	csx_decode_rd(opcode, &dpi.rd);
	csx_decode_shifter_operand(csx, opcode, &dpi);
	
	dpi.rd_v = dpi.out.v;

	dpi.mnemonic = "mov";
	if(!dpi.bit.i && (dpi.rd == dpi.rm))
		snprintf(dpi.op_string, 255, "/* nop */");
	else
		snprintf(dpi.op_string, 255, "/* 0x%08x */", dpi.rd_v);
	
	csx_inst_dpi_final(csx, opcode, &dpi, cce, 1);
}

#define CSX_INST_BIT_R_MASK (1 << 22)

static void csx_inst_mrs(csx_p csx, uint32_t opcode, uint8_t cce)
{
	_setup_decode_rd(opcode, rd);

	const char* psrs;
	uint32_t rd_v;

	if(opcode & CSX_INST_BIT_R_MASK)
	{
		psrs = "SPSR";
		rd_v = csx->spsr;
	}
	else
	{
		psrs = "CPSR";
		rd_v = csx->cpsr;
	}

	ITRACE("mrs(r[%hhu], %s) /* 0x%08x */", rd, psrs, rd_v);

	if(cce)
		csx_reg_set(csx, rd, rd_v);
}

static void csx_inst_orr(csx_p csx, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;
	
	csx_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_decode_shifter_operand(csx, opcode, &dpi);

	dpi.rn_v = csx_reg_get(csx, dpi.rn);
	dpi.rd_v = dpi.rn_v | dpi.out.v;

	dpi.mnemonic = "orr";
	snprintf(dpi.op_string, 255,
		"/* 0x%08x | 0x%08x --> 0x%08x */",
		dpi.rn_v, dpi.out.v, dpi.rd_v);
	
	csx_inst_dpi_final(csx, opcode, &dpi, cce, 1);
}

static void csx_inst_sub(csx_p csx, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;
	
	csx_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_decode_shifter_operand(csx, opcode, &dpi);

	dpi.flag_mode = CSX_CC_FLAGS_MODE_SUB;

	dpi.rn_v = csx_reg_get(csx, dpi.rn);
	dpi.rd_v = dpi.rn_v - dpi.out.v;

	dpi.mnemonic = "sub";
	snprintf(dpi.op_string, 255,
		"/* 0x%08x - 0x%08x --> 0x%08x */",
		dpi.rn_v, dpi.out.v, dpi.rd_v);
	
	csx_inst_dpi_final(csx, opcode, &dpi, cce, 1);
}

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

uint8_t csx_core_check_cc(csx_p csx, uint32_t opcode)
{
	uint32_t psr = csx->cpsr;
	uint8_t cc = _bits(opcode, 31, 28) & 0x0f;
	
	csx->ccs = inst_ccs[cc];

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
			csx->state |= CSX_STATE_HALT;
			TRACE("opcode = 0x%08x, cc = %02x, cpsr = 0x%08x, cpsr_cc %02x",
				opcode, cc, csx->cpsr, csx->cpsr >> (32 - 4));
			exit(1);
			break;
	}
	
	return(res);
}

#define _INST1(_x1)			(((_x1) & 0x07) << 25)
#define _INST1_2(_x1, _x2)	(_INST1(_x1) | (((_x2) & 0x0f) << 21))

#define CSX_INST1_INST3		_INST1(0x0)
#define CSX_INST1_LDST		_INST1(0x2)
#define CSX_INST1_INST2		_INST1(0x4)
#define CSX_INST1_MASK		_INST1(0x6)

#define CSX_INST2_B			_INST1(0x5)
#define CSX_INST2_MASK		_INST1(0x7)

#define CSX_INST3_AND		_INST1_2(0x0, 0x0)
#define CSX_INST3_SUB		_INST1_2(0x0, 0x2)
#define CSX_INST3_MRS		_INST1_2(0x0, 0x8)
#define CSX_INST3_CMP		_INST1_2(0x0, 0xa)
#define CSX_INST3_ORR		_INST1_2(0x0, 0xc)
#define CSX_INST3_MOV		_INST1_2(0x0, 0xd)
#define CSX_INST3_BIC		_INST1_2(0x0, 0xe)
#define CSX_INST3_MASK		_INST1_2(0x6, 0xf)

void csx_core_step(csx_p csx)
{
	uint32_t pc = csx_reg_get(csx, INSN_PC);
	csx_reg_set(csx, rPC, pc + 4);
	
	uint32_t opcode = csx_mmu_read(csx, pc, sizeof(uint32_t));

	uint8_t cce = !!csx_core_check_cc(csx, opcode);

	uint32_t check = opcode & CSX_INST1_MASK;

	uint8_t ci1 = _bits(opcode, 27, 25) & 0x6;
	uint8_t ci2 = _bits(opcode, 27, 25) & 0x7;
	uint8_t ci3 = _bits(opcode, 24, 21);
	
check01:
	switch(check)	/* check 1 */
	{
		case CSX_INST1_LDST:
			csx_inst_ldst(csx, opcode, cce);
			break;
		case CSX_INST1_INST2:
			goto check12;
		case CSX_INST1_INST3:
			goto check13;
		default:
			TRACE("opcode = 0x%08x, check = 0x%08x, ci1 = 0x%02hhx, ci2 = 0x%02hhx, ci3 = 0x%02hhx",
				opcode, check, ci1, ci2, ci3);
			exit(1);
			break;
	}
	return;

check12:
	check = opcode & CSX_INST2_MASK;
	switch(check)	/* check 2 */
	{
		case CSX_INST2_B:
			csx_inst_b(csx, opcode, cce);
			break;
		default:
			TRACE("opcode = 0x%08x, check = 0x%08x, ci1 = 0x%02hhx, ci2 = 0x%02hhx, , ci3 = 0x%02hhx",
				opcode, check, ci1, ci2, ci3);
			exit(1);
			break;
	}
	return;
	
check13:
	check = opcode & CSX_INST3_MASK;
	switch(check)	/* check 2 */
	{
		case CSX_INST3_AND:
			csx_inst_and(csx, opcode, cce);
			break;
		case CSX_INST3_BIC:
			csx_inst_bic(csx, opcode, cce);
			break;
		case CSX_INST3_CMP:
			csx_inst_cmp(csx, opcode, cce);
			break;
		case CSX_INST3_MOV:
			csx_inst_mov(csx, opcode, cce);
			break;
		case CSX_INST3_MRS:
			csx_inst_mrs(csx, opcode, cce);
			break;
		case CSX_INST3_ORR:
			csx_inst_orr(csx, opcode, cce);
			break;
		case CSX_INST3_SUB:
			csx_inst_sub(csx, opcode, cce);
			break;
		default:
			TRACE("opcode = 0x%08x, check = 0x%08x, ci1 = 0x%02hhx, ci2 = 0x%02hhx, ci3 = 0x%02hhx",
				opcode, check, ci1, ci2, ci3);
			exit(1);
			break;
	}
}


void csx_core_reset(csx_p csx)
{
	csx->cpsr = (0xe << 5) | 13;

	csx_reg_set(csx, INSN_PC, 0);
	
	TRACE("cpsr = 0x%08x", csx->cpsr);
}

int csx_core_init(csx_p* ccsx)
{
	int err;
	csx_p csx = *ccsx;
	
	ERR(err = csx_mmu_init(csx));
	ERR(err = csx_mmio_init(csx));

	csx_core_reset(csx);

	return(err);
}
