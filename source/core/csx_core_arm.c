#include "csx.h"
#include "csx_core.h"

#include "csx_core_arm.h"
#include "csx_core_arm_inst.h"

static void arm_inst_dpi_final(csx_core_p core, uint32_t opcode, csx_dpi_p dpi, uint8_t cce)
{
	csx_trace_inst_dpi(core, opcode, dpi, cce);

	if(cce)
	{
		if(dpi->wb)
			csx_reg_set(core, dpi->rd, dpi->rd_v);

		if(dpi->bit.s)
		{
			if(rPC == dpi->rd /* && PSR = CPSR*/)
			{
				TRACE();
				exit(1);
			}
			else
			{
				uint32_t rd_v = dpi->rd_v;
				uint32_t s1_v = dpi->rn_v;
				uint32_t s2_v = dpi->out.v;

				switch(dpi->flag_mode)
				{
					case CSX_CC_FLAGS_MODE_ADD:
					case CSX_CC_FLAGS_MODE_SUB:
						csx_core_flags_nzcv(core, rd_v, s1_v, s2_v);
						break;
					default:
						csx_core_flags_nz(core, rd_v);
						CPSR &= ~CSX_PSR_C;
						CPSR |= (dpi->out.c ? CSX_PSR_C : 0);
						break;
				}
			}
		}
	}
}

static void arm_inst_add(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;

	csx_core_arm_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	dpi.flag_mode = CSX_CC_FLAGS_MODE_ADD;

	dpi.rn_v = csx_reg_get(core, dpi.rn);
	dpi.rd_v = dpi.rn_v + dpi.out.v;

	dpi.mnemonic = "add";
	snprintf(dpi.op_string, 255,
		"/* 0x%08x + 0x%08x --> 0x%08x */",
		dpi.rn_v, dpi.out.v, dpi.rd_v);

	arm_inst_dpi_final(core, opcode, &dpi, cce);
}

static void arm_inst_and(csx_core_p core, uint32_t opcode, uint32_t cce)
{
	csx_dpi_t	dpi;

	csx_core_arm_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	dpi.rn_v = csx_reg_get(core, dpi.rn);
	dpi.rd_v = dpi.rn_v & dpi.out.v;

	dpi.mnemonic = "and";

	snprintf(dpi.op_string, 255,
		"/* 0x%08x & 0x%08x --> 0x%08x, cce = %u, ccs = %s*/",
		dpi.rn_v, dpi.out.v, dpi.rd_v, cce, core->ccs);

	arm_inst_dpi_final(core, opcode, &dpi, cce);

	if(1) TRACE("N = %1u, Z = %1u, C = %1u, V = %1u",
		!!(CPSR & CSX_PSR_N), !!(CPSR & CSX_PSR_Z),
		!!(CPSR & CSX_PSR_C), !!(CPSR & CSX_PSR_V));
}

static void arm_inst_b(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	int link = BIT_OF(opcode, ARM_INST_BIT_LINK);
	int32_t offset = _bits_sext(opcode, 23, 0);

	uint32_t pc = csx_reg_get(core, rPC);

	uint32_t new_pc = pc + (offset << 2);

	CORE_TRACE("b%s(0x%08x) /* 0x%08x */", link ? "l" : "", new_pc, offset);

	if(cce)
	{
		if(link)
			csx_reg_set(core, rLR, pc);

		csx_reg_set(core, rPC, new_pc);
		core->csx->cycle += 2;
	}
}

static void arm_inst_bic(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;

	csx_core_arm_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	dpi.rn_v = csx_reg_get(core, dpi.rn);
	dpi.rd_v = dpi.rn_v & !dpi.out.v;

	dpi.mnemonic = "bic";

	snprintf(dpi.op_string, 255,
		"/* 0x%08x & !0x%08x(0x%08x) --> 0x%08x */",
		dpi.rn_v, dpi.out.v, !dpi.out.v, dpi.rd_v);

	arm_inst_dpi_final(core, opcode, &dpi, cce);
}

static void arm_inst_bx(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	_setup_decode_rm(opcode, rm);
	uint32_t rm_v = csx_reg_get(core, rm);
	
	CORE_TRACE("bx(0x%08x)", rm_v);

	if(cce)
	{
		csx_reg_set(core, rPC, rm_v);
		
		CPSR &= ~CSX_PSR_T;
		CPSR |= BIT2BIT(rm_v, 1, CSX_PSR_BIT_T);
		
		core->csx->cycle += 2;
	}
}

static void arm_inst_cmp(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;

	csx_core_arm_decode_rn(opcode, &dpi.rn);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	dpi.wb = 0;
	dpi.flag_mode = CSX_CC_FLAGS_MODE_SUB;

	dpi.rn_v = csx_reg_get(core, dpi.rn);
	dpi.rd_v = dpi.rn_v - dpi.out.v;

	dpi.mnemonic = "cmp";

	snprintf(dpi.op_string, 255,
		"/* 0x%08x - 0x%08x ??? 0x%08x */",
		dpi.rn_v, dpi.out.v, dpi.rd_v);

	arm_inst_dpi_final(core, opcode, &dpi, cce);
}

static void arm_inst_ldst(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_p csx = core->csx;
	
	csx_ldst_t ls;
	csx->cycle++;

	csx_core_arm_decode_ldst(core, opcode, &ls);
	if((0x01 != ls.bit.i2x_76) && !ls.bit.i25)
	{
		if(!ls.bit.i22)
		{
			csx->cycle++;
			ls.rm_v = csx_reg_get(core, ls.rm);
		}
	}

	ls.rn_v = csx_reg_get(core, ls.rn);
	if(ls.bit.u)
		ls.ea = ls.rn_v + ls.rm_v;
	else
		ls.ea = ls.rn_v - ls.rm_v;

	if(ls.bit.l)
		ls.rd_v = csx->mmu.read(csx, ls.ea, ls.rw_size);
	else
		ls.rd_v = csx_reg_get(core, ls.rd);
	
	csx_trace_inst_ldst(core, opcode, &ls, cce);

	if(cce)
	{
		if(!!ls.bit.p && !!ls.bit.w) /* base update? */
			LOG_ACTION(csx->state = CSX_STATE_HALT);

		if(ls.bit.l)
		{
			csx_reg_set(core, ls.rd, ls.rd_v);
		}
		else
			csx->mmu.write(csx, ls.ea, ls.rd_v, ls.rw_size);
	}
}

static void arm_inst_mcr(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_coproc_data_t acp;
	
	csx_core_arm_decode_coproc(core, opcode, &acp);

	if(acp.bit.l)
	{
		csx_coprocessor_read(core->csx, &acp);
		CORE_TRACE("mrc(p(%u), %u, rd(%u), cn(%u), cm(%u), %u)",
			acp.cp_num, acp.opcode1, acp.rd,
			acp.crn, acp.crm, acp.opcode2);
	}
	else
	{
		CORE_TRACE("mcr(p(%u), %u, rd(%u), cn(%u), cm(%u), %u)",
			acp.cp_num, acp.opcode1, acp.rd,
			acp.crn, acp.crm, acp.opcode2);
		csx_coprocessor_write(core->csx, &acp);
	}
}

static void arm_inst_mov(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	uint32_t test, result;

	int tsbz = _check_sbz(opcode, 19, 16, &test, &result);
	if(tsbz)
	{
		TRACE("!! sbz(19, 16, =0x%08x, =0x%08x (%u))", test, result, tsbz);
		abort();
	}

	csx_dpi_t	dpi;

	dpi.rn = -1;

	csx_core_arm_decode_rd(opcode, &dpi.rd);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	dpi.rd_v = dpi.out.v;

	dpi.mnemonic = "mov";
	if(!dpi.bit.i && (dpi.rd == dpi.rm))
		snprintf(dpi.op_string, 255, "/* nop */");
	else
		snprintf(dpi.op_string, 255, "/* 0x%08x */", dpi.rd_v);

	arm_inst_dpi_final(core, opcode, &dpi, cce);
}

static void arm_inst_mrs(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	uint32_t test, result;

	int tsbo = _check_sbo(opcode, 19, 16, &test, &result);
	if(tsbo)
		TRACE("!! sbo(opcode = 0x%08x, 19, 16, =0x%08x, =0x%08x (%u))", opcode, test, result, tsbo);

	int tsbz = _check_sbz(opcode, 11, 0, &test, &result);
	if(tsbz)
		TRACE("!! sbz(opcode = 0x%08x, 11, 0, =0x%08x, =0x%08x (%u))", opcode, test, result, tsbz);

	if(tsbo || tsbz)
		abort();

	_setup_decode_rd(opcode, rd);

	const char* psrs;
	uint32_t rd_v;

	if(BIT_OF(opcode, ARM_INST_BIT_R))
	{
		psrs = "SPSR";
		rd_v = core->spsr;
	}
	else
	{
		psrs = "CPSR";
		rd_v = CPSR;
	}

	CORE_TRACE("mrs(r(%u), %s) /* 0x%08x */", rd, psrs, rd_v);

	if(cce)
		csx_reg_set(core, rd, rd_v);
}

static const uint32_t csx_msr_priv_mask[] = 
	{ 0x0000000f, 0x0000000f, 0x0000000f, 0x0000000f, 0x000001df };
static const uint32_t csx_msr_state_mask[] = 
	{ 0x00000000, 0x00000020, 0x00000020, 0x01000020, 0x01000020 };
static const uint32_t csx_msr_unalloc_mask[] = 
	{ 0x0fffff20, 0x0fffff00, 0x07ffff00, 0x06ffff00, 0x06f0fc00 };
static const uint32_t csx_msr_user_mask[] = 
	{ 0xf0000000, 0xf0000000, 0xf8000000, 0xf8000000, 0xf80f0200 };

static void arm_inst_msr(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_p csx = core->csx;
	
	uint32_t test, result;

	int tsbo = _check_sbo(opcode, 15, 12, &test, &result);
	if(tsbo)
		TRACE("!! sbo(opcode = 0x%08x, 15, 12, =0x%08x, =0x%08x (%u))", opcode, test, result, tsbo);

	struct {
		uint8_t i;
		uint8_t r;
	}bit;

	bit.i = BIT_OF(opcode, 25);
	bit.r = BIT_OF(opcode, 22);
	
	uint8_t field_mask = _bits(opcode, 19, 16);
	
	uint8_t rotate_imm, imm8;
	uint8_t rm, rm_v;
	uint8_t operand;
	
	if(bit.i)
	{
		rotate_imm = _bits(opcode, 11, 8);
		imm8 = _bits(opcode, 7, 0);
		operand = imm8 << (rotate_imm << 1);
	}
	else
	{
		if(0 == _bits(opcode, 7, 4))
		{
			int tsbz = _check_sbz(opcode, 11, 8, &test, &result);
			if(tsbz)
				TRACE("!! sbz(opcode = 0x%08x, 11, 8, =0x%08x, =0x%08x (%u))", opcode, test, result, tsbz);

			rm = _bits(opcode, 3, 0);
			rm_v = csx_reg_get(core, rm);
			operand = rm_v;
		}
		else
		{
			LOG_ACTION(csx->state |= CSX_STATE_HALT);
		}
	}

	uint32_t unalloc_mask = csx_msr_unalloc_mask[arm_v5tej];
	TRACE("unalloc_mask = 0x%08x", unalloc_mask);

	if(operand & unalloc_mask)
	{
		LOG_ACTION(csx->state |= CSX_STATE_HALT);
		UNPREDICTABLE;
	}

	uint32_t byte_mask = 0;
	byte_mask |= BIT_OF(field_mask, 0) ? (0xff << 0) : 0;
	byte_mask |= BIT_OF(field_mask, 1) ? (0xff << 8) : 0;
	byte_mask |= BIT_OF(field_mask, 2) ? (0xff << 16) : 0;
	byte_mask |= BIT_OF(field_mask, 3) ? (0xff << 24) : 0;
	
	uint32_t state_mask = csx_msr_state_mask[arm_v5tej];
	uint32_t user_mask = csx_msr_user_mask[arm_v5tej];
	uint32_t priv_mask = csx_msr_priv_mask[arm_v5tej];
	
	TRACE("state_mask = 0x%08x, user_mask = 0x%08x, priv_mask = 0x%08x",
		state_mask, user_mask, priv_mask);
		
	TRACE("field_mask = 0x%08x, byte_mask = 0x%08x", field_mask, byte_mask);
	
	uint32_t saved_psr, new_psr;
	
	uint32_t mask;
	if(bit.r)
	{
		if(csx_current_mode_has_spsr(core))
		{
			mask = byte_mask & (user_mask | priv_mask | state_mask);
			
			saved_psr = core->spsr;
			new_psr = (saved_psr & ~mask) | (operand & mask);
			
			if(cce)
				core->spsr = new_psr;
		}
		else
		{
			LOG_ACTION(csx->state |= CSX_STATE_HALT);
			UNPREDICTABLE;
		}
	}
	else
	{
		if(csx_in_a_privaleged_mode(core))
		{
			if(operand & state_mask)
			{
				LOG_ACTION(csx->state |= CSX_STATE_HALT);
				UNPREDICTABLE;
			}
			else
				mask = byte_mask & (user_mask | priv_mask);
		}
		else
			mask = byte_mask & user_mask;

		saved_psr = CPSR;
		new_psr = (saved_psr & ~mask) | (operand & mask);

		if(cce)
			csx_psr_mode_switch(core, new_psr);
	}
	
	uint8_t cpsrs[5];
	cpsrs[0] = BIT_OF(field_mask, 3) ? 'F' : 'f';
	cpsrs[1] = BIT_OF(field_mask, 2) ? 'S' : 's';
	cpsrs[2] = BIT_OF(field_mask, 1) ? 'X' : 'x';
	cpsrs[3] = BIT_OF(field_mask, 0) ? 'C' : 'c';
	cpsrs[4] = 0;
	
	uint8_t cs = bit.r ? 'S' : 'C';
	
	csx_trace_psr(core, 0, saved_psr);

	if(bit.i)
	{
		CORE_TRACE("msr(%cPSR_%s, 0x%08x) /* 0x%08x & 0x%08x -> 0x%08x */", cs, cpsrs, operand, operand, mask, operand & mask);
	}
	else
	{
		CORE_TRACE("msr(%cPSR_%s, rm(%u)) /* 0x%08x & 0x%08x -> 0x%08x*/", cs, cpsrs, rm, operand, mask, operand & mask);
	}
	
	csx_trace_psr(core, 0, new_psr);
}

static void arm_inst_mvn(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	uint32_t test, result;

	int tsbz = _check_sbz(opcode, 19, 16, &test, &result);
	if(tsbz)
	{
		TRACE("!! sbz(19, 16, =0x%08x, =0x%08x (%u))", test, result, tsbz);
		abort();
	}

	csx_dpi_t	dpi;

	dpi.rn = -1;

	csx_core_arm_decode_rd(opcode, &dpi.rd);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	dpi.rd_v = 0xffffffff ^ dpi.out.v;

	dpi.mnemonic = "mvn";
	snprintf(dpi.op_string, 255, "/* 0x%08x */", dpi.rd_v);

	arm_inst_dpi_final(core, opcode, &dpi, cce);
}

static void arm_inst_orr(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;

	csx_core_arm_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	dpi.rn_v = csx_reg_get(core, dpi.rn);
	dpi.rd_v = dpi.rn_v | dpi.out.v;

	dpi.mnemonic = "orr";
	snprintf(dpi.op_string, 255,
		"/* 0x%08x | 0x%08x --> 0x%08x */",
		dpi.rn_v, dpi.out.v, dpi.rd_v);

	arm_inst_dpi_final(core, opcode, &dpi, cce);
}

static void arm_inst_sub(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;

	csx_core_arm_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	dpi.flag_mode = CSX_CC_FLAGS_MODE_SUB;

	dpi.rn_v = csx_reg_get(core, dpi.rn);
	dpi.rd_v = dpi.rn_v - dpi.out.v;

	dpi.mnemonic = "sub";
	snprintf(dpi.op_string, 255,
		"/* 0x%08x - 0x%08x --> 0x%08x */",
		dpi.rn_v, dpi.out.v, dpi.rd_v);

	arm_inst_dpi_final(core, opcode, &dpi, cce);
}

/* **** */

static uint8_t csx_core_arm_check_cc(csx_core_p core, uint32_t opcode)
{
	uint8_t cc = _bits(opcode, 31, 28) & 0x0f;
	return(csx_core_check_cc(core, opcode, cc));
}

#define _INST1(_x1)			(((_x1) & 0x07) << 25)
#define _INST1_2(_x1, _x2)	(_INST1(_x1) | (((_x2) & 0x0f) << 21))

#define CORE_ARM1_INST3		_INST1(0x0)
#define CORE_ARM1_LDST		_INST1(0x2)
#define CORE_ARM1_INST2		_INST1(0x4)
#define CORE_ARM1_COPROC	_INST1(0x6)
#define CORE_ARM1_MASK		_INST1(0x6)

#define CORE_ARM2_B			_INST1(0x5)
#define CORE_ARM2_MASK		_INST1(0x7)

#define CORE_ARM3_AND		_INST1_2(0x0, 0x0)
#define CORE_ARM3_SUB		_INST1_2(0x0, 0x2)
#define CORE_ARM3_ADD		_INST1_2(0x0, 0x4)
#define CORE_ARM3_MRS		_INST1_2(0x0, 0x8)
#define CORE_ARM3_CMP		_INST1_2(0x0, 0xa)
#define CORE_ARM3_ORR		_INST1_2(0x0, 0xc)
#define CORE_ARM3_MOV		_INST1_2(0x0, 0xd)
#define CORE_ARM3_BIC		_INST1_2(0x0, 0xe)
#define CORE_ARM3_MVN		_INST1_2(0x0, 0xf)
#define CORE_ARM3_MASK		_INST1_2(0x6, 0xf)

#define CORE_ARM3_LDST		(_BV(7) | _BV(4))
#define CORE_ARM3_LDST_MASK	(_INST1(7) | CORE_ARM3_LDST)

#define CORE_ARM_DPI(_x2)	_INST1_2(0x01, _x2)
#define CORE_ARM_DPIS(_x2)	_INST1_2(0x01, _x2)
#define CORE_ARM_DPRS(_x2)	_INST1_2(0x01, _x2) | _BV(4)

#define CORE_ARM_DPIS_MASK	_INST1_2(0x07, 0x0f) | _BV(4)
#define CORE_ARM_DPRS_MASK	_INST1_2(0x07, 0x0f) | _BV(7) | _BV(4)

void csx_core_arm_step(csx_core_p core)
{
	uint32_t pc = csx_reg_get(core, INSN_PC);

	if(pc & 1) {
		LOG("!! pc & 1");
		exit(1);
	}

	core->csx->cycle++;

	csx_reg_set(core, rPC, pc + 4);

	uint32_t ir = core->csx->mmu.read(core->csx, pc, sizeof(uint32_t));

	uint8_t cce = csx_core_arm_check_cc(core, ir);

	uint8_t ci1 = _bits(ir, 27, 25) & 0x06;
	uint8_t ci2 = _bits(ir, 27, 25) & 0x07;
	uint8_t ci3 = _bits(ir, 24, 21);
	uint8_t	i74 = BIT2BIT(ir, 25, 2) | BIT2BIT(ir, 7, 1) | BIT_OF(ir, 4);

	uint32_t check = ir & CORE_ARM1_MASK;

//check1:
	switch(check)	/* check 1 */
	{
		case CORE_ARM1_COPROC:
			goto check_inst_coproc;
			break;
		case CORE_ARM1_LDST:
			arm_inst_ldst(core, ir, cce);
			break;
		case CORE_ARM1_INST2:
			goto check2;
		case CORE_ARM1_INST3:
			goto check3;
		default:
			TRACE("::1 >> ir = 0x%08x, check1 = 0x%08x, ci1 = 0x%02hhx, ci2 = 0x%02hhx, ci3 = 0x%02hhx, i74 = 0x%02hhx",
				ir, check, ci1, ci2, ci3, i74);
			exit(1);
			break;
	}
	return;

check2:
	check = ir & CORE_ARM2_MASK;
	switch(check)	/* check 2 */
	{
		case CORE_ARM2_B:
			arm_inst_b(core, ir, cce);
			break;
		default:
			TRACE("::2 >> ir = 0x%08x, check = 0x%08x, ci1 = 0x%02hhx, ci2 = 0x%02hhx, ci3 = 0x%02hhx, i74 = 0x%02hhx",
				ir, check, ci1, ci2, ci3, i74);
			exit(1);
			break;
	}
	return;

check3:
	if(CORE_ARM3_LDST == (ir & CORE_ARM3_LDST_MASK))
	{
		arm_inst_ldst(core, ir, cce);
		return;
	}
	else if(ARM_INST_BX == (ir & ARM_INST_BX_MASK))
	{
		arm_inst_bx(core, ir, cce);
		return;
	}
	else if(ARM_INST_MSR == (ir & ARM_INST_MSR_MASK))
	{
		arm_inst_msr(core, ir, cce);
		return;
	}

	check = ir & CORE_ARM3_MASK;
	switch(check)	/* check 3 */
	{
		case CORE_ARM3_ADD:
			arm_inst_add(core, ir, cce);
			break;
		case CORE_ARM3_AND:
			arm_inst_and(core, ir, cce);
			break;
		case CORE_ARM3_BIC:
			arm_inst_bic(core, ir, cce);
			break;
		case CORE_ARM3_CMP:
			arm_inst_cmp(core, ir, cce);
			break;
		case CORE_ARM3_MOV:
			arm_inst_mov(core, ir, cce);
			break;
		case CORE_ARM3_MRS:
			arm_inst_mrs(core, ir, cce);
			break;
		case CORE_ARM3_MVN:
			arm_inst_mvn(core, ir, cce);
			break;
		case CORE_ARM3_ORR:
			arm_inst_orr(core, ir, cce);
			break;
		case CORE_ARM3_SUB:
			arm_inst_sub(core, ir, cce);
			break;
		default:
			TRACE("::3 >> opcode = 0x%08x, check = 0x%08x, ci1 = 0x%02hhx, ci2 = 0x%02hhx, ci3 = 0x%02hhx, i74 = 0x%02hhx",
				ir, check, ci1, ci2, ci3, i74);
			csx_core_disasm(core, pc, ir);
			exit(1);
			break;
	}
	return;

check_inst_coproc:
	check = ir & ARM_INST_MCR_MASK;
	if(ARM_INST_MCR == check)
		arm_inst_mcr(core, ir, cce);
	else
	{
		TRACE("opcode = 0x%08x", ir);
		csx_core_disasm(core, pc, ir);
		exit(1);
	}
}
