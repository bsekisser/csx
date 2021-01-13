#include <assert.h>

#include "csx.h"
#include "csx_core.h"

#include "csx_core_arm_inst.h"

static const char* _arm_creg_name(csx_reg_t r)
{
	const char* creg_names[16] = {
		"c0",	"c1",	"c2",	"c3",	"c4",	"c5",	"c6",	"c7",
		"c8",	"c9",	"c10",	"c11",	"c12",	"c13",	"c14",	"c15",
	};
	
	return(creg_names[r]);
}

const char* _arm_reg_name(csx_reg_t r)
{
	const char* reg_names[16] = {
		"r0",	"r1",	"r2",	"r3",	"r4",	"r5",	"r6",	"r7",
		"r8",	"r9",	"r10",	"r11",	"r12",	"rSP",	"rLR",	"rPC",
	};
	
	return(reg_names[r]);
}

static void arm_inst_dpi_final(csx_core_p core, uint32_t opcode, csx_dpi_p dpi, uint8_t cce)
{
	csx_trace_inst_dpi(core, opcode, dpi, cce);

	if(cce)
	{
		if(dpi->wb)
			csx_reg_set(core, dpi->rd, dpi->rd_v);

		if(dpi->bit.s)
		{
			if(rPC == dpi->rd)
			{
				if(core->spsr)
					csx_psr_mode_switch(core, *core->spsr);
				else
					UNPREDICTABLE;
			}
			else
			{
				uint32_t rd_v = dpi->rd_v;
				uint32_t s1_v = dpi->rn_v;
				uint32_t s2_v = dpi->out.v;

				switch(dpi->operation)
				{
					case ARM_DPI_OPERATION_ADD:
					case ARM_DPI_OPERATION_CMP:
					case ARM_DPI_OPERATION_SUB:
						csx_core_flags_nzcv(core, rd_v, s1_v, s2_v);
						break;
					default:
						csx_core_flags_nz(core, rd_v);
						BMAS(CPSR, CSX_PSR_BIT_C, dpi->out.c);
						break;
				}
			}
		}
	}
}

static void arm_inst_dpi_operation_add(csx_core_p core, csx_dpi_p dpi)
{
	dpi->rd_v = dpi->rn_v + dpi->out.v;

	dpi->mnemonic = "add";
	snprintf(dpi->op_string, 255,
		"/* 0x%08x + 0x%08x --> 0x%08x */",
		dpi->rn_v, dpi->out.v, dpi->rd_v);
}

static void arm_inst_dpi_operation_and(csx_core_p core, csx_dpi_p dpi)
{
	dpi->rd_v = dpi->rn_v & dpi->out.v;

	dpi->mnemonic = "and";

	snprintf(dpi->op_string, 255,
		"/* 0x%08x & 0x%08x --> 0x%08x */",
		dpi->rn_v, dpi->out.v, dpi->rd_v);
}

static void arm_inst_dpi_operation_bic(csx_core_p core, csx_dpi_p dpi)
{
	dpi->rd_v = dpi->rn_v & !dpi->out.v;

	dpi->mnemonic = "bic";

	snprintf(dpi->op_string, 255,
		"/* 0x%08x & !0x%08x(0x%08x) --> 0x%08x */",
		dpi->rn_v, dpi->out.v, !dpi->out.v, dpi->rd_v);
}

static void arm_inst_dpi_operation_cmp(csx_core_p core, csx_dpi_p dpi)
{
	dpi->wb = 0;
	dpi->rd_v = dpi->rn_v - dpi->out.v;

	dpi->mnemonic = "cmp";

	snprintf(dpi->op_string, 255,
		"/* 0x%08x - 0x%08x ??? 0x%08x */",
		dpi->rn_v, dpi->out.v, dpi->rd_v);
}

static void arm_inst_dpi_operation_mov(csx_core_p core, csx_dpi_p dpi)
{
	if(dpi->rn)
	{
		LOG("!! rn(%u) -- sbz", dpi->rn);
		LOG_ACTION(exit(1));
	}

	dpi->rn = -1;
	dpi->rd_v = dpi->out.v;

	dpi->mnemonic = "mov";
	
	if(!dpi->bit.i && (dpi->rd == dpi->rm))
		snprintf(dpi->op_string, 255, "/* nop */");
	else
		snprintf(dpi->op_string, 255, "/* 0x%08x */", dpi->rd_v);
}

static void arm_inst_dpi_operation_mvn(csx_core_p core, csx_dpi_p dpi)
{
	if(dpi->rn)
	{
		LOG("!! rn(%u) -- sbz", dpi->rn);
		LOG_ACTION(exit(1));
	}

	dpi->rn = -1;
	dpi->rd_v = ~dpi->out.v;

	dpi->mnemonic = "mvn";
	snprintf(dpi->op_string, 255, "/* 0x%08x */", dpi->rd_v);
}

static void arm_inst_dpi_operation_orr(csx_core_p core, csx_dpi_p dpi)
{
	dpi->rd_v = dpi->rn_v | dpi->out.v;

	dpi->mnemonic = "orr";
	snprintf(dpi->op_string, 255,
		"/* 0x%08x | 0x%08x --> 0x%08x */",
		dpi->rn_v, dpi->out.v, dpi->rd_v);
}

static void arm_inst_dpi_operation_sub(csx_core_p core, csx_dpi_p dpi)
{
	dpi->rd_v = dpi->rn_v - dpi->out.v;

	dpi->mnemonic = "sub";
	snprintf(dpi->op_string, 255,
		"/* 0x%08x - 0x%08x --> 0x%08x */",
		dpi->rn_v, dpi->out.v, dpi->rd_v);
}

static void arm_inst_dpi(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_dpi_t	dpi;

	csx_core_arm_decode_rn_rd(opcode, &dpi.rn, &dpi.rd);
	csx_core_arm_decode_shifter_operand(core, opcode, &dpi);

	if(ARM_DPI_OPERATION_MOV != dpi.operation)
		dpi.rn_v = csx_reg_get(core, dpi.rn);

	switch(dpi.operation)
	{
		case ARM_DPI_OPERATION_ADD:
			arm_inst_dpi_operation_add(core, &dpi);
			break;
		case ARM_DPI_OPERATION_AND:
			arm_inst_dpi_operation_and(core, &dpi);
			break;
		case ARM_DPI_OPERATION_BIC:
			arm_inst_dpi_operation_bic(core, &dpi);
			break;
		case ARM_DPI_OPERATION_CMP:
			if(dpi.bit.s)
				arm_inst_dpi_operation_cmp(core, &dpi);
			else
				goto exit_fault;
			break;
		case ARM_DPI_OPERATION_MOV:
			arm_inst_dpi_operation_mov(core, &dpi);
			break;
		case ARM_DPI_OPERATION_MVN:
			arm_inst_dpi_operation_mvn(core, &dpi);
			break;
		case ARM_DPI_OPERATION_ORR:
			arm_inst_dpi_operation_orr(core, &dpi);
			break;
		case ARM_DPI_OPERATION_SUB:
			arm_inst_dpi_operation_sub(core, &dpi);
			break;
		default:
			goto exit_fault;
			break;
	}
	
	arm_inst_dpi_final(core, opcode, &dpi, cce);
	return;

exit_fault:
	LOG("operation = 0x%02x", dpi.operation);
	csx_core_disasm(core, core->pc, opcode);
	LOG_ACTION(exit(1));
}


static void arm_inst_b(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	int link = BEXT(opcode, ARM_INST_BIT_LINK);
	int32_t offset = BFSEXT(opcode, 23, 0);

	uint32_t pc = csx_reg_get(core, rPC);

	uint32_t new_pc = pc + (offset << 2);

	uint8_t blx = (0x0f == BFEXT(opcode, 31, 28));
	
	if(blx)
	{
		new_pc |= (link << 1) | 1;
		core->ccs = "AL";
		link = cce = 1;
	}

	CORE_TRACE("b%s%s(0x%08x) /* 0x%08x */",
		link ? "l" : "", blx ? "x" : "", new_pc & ~1, offset);

	if(cce)
	{
		if(link)
			csx_reg_set(core, rLR, csx_reg_get(core, TEST_PC));

		core->csx->cycle += 3;
		
		if(blx)
			csx_reg_set(core, INSN_PC, new_pc);
		else
			csx_reg_set(core, rPC, new_pc);
	}
}

static void arm_inst_bx(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	_setup_decode_rm(opcode, rm);
	int link = BEXT(opcode, 5);

	uint32_t rm_v = csx_reg_get(core, rm);

	CORE_TRACE("b%sx(r(%u)) /* 0x%08x */", link ? "l" : "", rm, rm_v & ~1);

	if(cce)
	{
		if(link)
			csx_reg_set(core, rLR, csx_reg_get(core, TEST_PC));
		
		core->csx->cycle += 3;
		csx_reg_set(core, INSN_PC, rm_v);
	}
}

static void arm_inst_ldst(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_p csx = core->csx;
	
	csx_ldst_t ls;
	csx_core_arm_decode_ldst(core, opcode, &ls);

	csx->cycle++;

	if((ls.rm & 0x0f) == ls.rm)
	{
		csx->cycle++;
		ls.rm_v = csx_reg_get(core, ls.rm);
	}
	
	ls.rn_v = csx_reg_get(core, ls.rn);
	if(ls.bit.u)
		ls.ea = ls.rn_v + ls.rm_v;
	else
		ls.ea = ls.rn_v - ls.rm_v;

	if(ls.bit.l)
	{
		ls.rd_v = csx_mmu_read(csx->mmu, ls.ea, ls.rw_size);
		if(ls.flags.s)
			ls.rd_v = BFSEXT(ls.rd_v, (ls.rw_size << 2), 0);
	}
	else
		ls.rd_v = csx_reg_get(core, ls.rd);
	
	csx_trace_inst_ldst(core, opcode, &ls, cce);

	if(cce)
	{
		if(ls.bit.p && ls.bit.w) /* base update? */
			csx_reg_set(core, ls.rn, ls.ea);

		if(ls.bit.l)
		{
			csx_reg_set(core, ls.rd, ls.rd_v);
		}
		else
			csx_mmu_write(csx->mmu, ls.ea, ls.rd_v, ls.rw_size);
	}
}

static void _arm_inst_ldstm(csx_core_p core, csx_ldst_p ls, uint8_t i)
{
	csx_p csx = core->csx;
	uint32_t rxx_v;

	if(ls->bit.p)
		ls->ea += ls->bit.u ? 4 : -4;

	if(ls->bit.l)
	{
		rxx_v = csx_mmu_read(csx->mmu, ls->ea, sizeof(uint32_t));
		LOG("r(%u)==[0x%08x](0x%08x)", i, ls->ea, rxx_v);
		csx_reg_set(core, i, rxx_v);
	}
	else
	{
		rxx_v = csx_reg_get(core, i);
		LOG("[0x%08x]==r(%u)(0x%08x)", ls->ea, i, rxx_v);
		csx_mmu_write(csx->mmu, ls->ea, rxx_v, sizeof(uint32_t));
	}

	if(!ls->bit.p)
		ls->ea += ls->bit.u ? 4 : -4;
}

static void arm_inst_ldstm(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_p csx = core->csx;

	csx_ldst_t ls;
	csx_core_arm_decode_ldst(core, opcode, &ls);
	ls.rn_v = csx_reg_get(core, ls.rn);

	uint8_t ea_mode = BFEXT(opcode, 24, 23);
	uint8_t rcount = __builtin_popcount(ls.rm_v) << 2;
	
	uint32_t start_address = ls.rn_v;
	uint32_t end_address = ls.rn_v;
	
	switch(ea_mode)
	{
		case	0x00:	/*	DA	*/
			start_address -= rcount + 4;
			break;
		case	0x01:	/*	IA	*/
			end_address += rcount - 4;
			break;
		case	0x02:	/*	DB	*/
			start_address -= rcount;
			end_address -= 4;
			break;
		case	0x03:	/*	IB	*/
			start_address += 4;
			end_address += rcount;
			break;
	}

	const char *opstr;
	if(rSP == ls.rn)
		opstr = ls.bit.l ? "pop" : "push";
	else
		opstr = ls.bit.l ? "ldm" : "stm";

	LOG("%s, r(%u)(0x%08x), start_address = 0x%08x, end_address = 0x%08x",
		opstr, ls.rn, ls.rn_v, start_address, end_address);

//	ls.ea = start_address;
	ls.ea = ls.rn_v;
	
	uint32_t rxx_v;

	if(cce)
	{
		for(int i = 0; i < 15; i++)
		{
			if(BTST(ls.rm_v, i))
			{
				csx->cycle++;
				_arm_inst_ldstm(core, &ls, i);
			}
		}
		
		if(ls.bit.l && ls.bit.s && core->spsr)
			csx_psr_mode_switch(core, *core->spsr);
		
		if(BTST(ls.rm_v, 15))
		{
			if(ls.bit.p)
				ls.ea += ls.bit.u ? 4 : -4;

			csx->cycle++;
//			_arm_inst_ldstm(core, ls, 15);

			if(ls.bit.l)
			{
				rxx_v = csx_mmu_read(csx->mmu, ls.ea, sizeof(uint32_t));
				LOG("r(%u)==[0x%08x](0x%08x)", 15, ls.ea, rxx_v);
				csx_reg_set(core, INSN_PC, rxx_v);
			}
			else
			{
				rxx_v = csx_reg_get(core, rPC);
				LOG("[0x%08x]==r(%u)(0x%08x)", ls.ea, 15, rxx_v);
				csx_mmu_write(csx->mmu, ls.ea, rxx_v, sizeof(uint32_t));
			}

			if(ls.bit.p)
				ls.ea += ls.bit.u ? 4 : -4;

//			ls.ea += 4;
		}

		if(ls.bit.w) 
		{
			fflush(0);
			if(0) switch(ea_mode)
			{
				case 0x00:	/*	DA	*/
				case 0x02:	/*	DB	*/
					assert(end_address == ls.ea - 4);
//					assert(ls.ea == ls.rn - (rcount << 2));
					break;
				case 0x01:	/*	IA	*/
				case 0x03:	/*	IB	*/
					assert(ls.ea == ls.rn_v + rcount);
					break;
			}
			csx->cycle++;
			csx_reg_set(core, ls.rn, ls.ea);
		}
	}
}

static void arm_inst_mcr(csx_core_p core, uint32_t opcode, uint8_t cce)
{
	csx_p csx = core->csx;
	csx_coproc_data_t acp;
	
	csx_core_arm_decode_coproc(core, opcode, &acp);

	if(acp.bit.l)
	{
		csx_coprocessor_read(csx, &acp);
		CORE_TRACE("mrc(p(%u), %u, %s, cn(%u), cm(%u), %u)",
			acp.cp_num, acp.opcode1, _arm_reg_name(acp.rd),
			acp.crn, acp.crm, acp.opcode2);
	}
	else
	{
		CORE_TRACE("mcr(p(%u), %u, %s, cn(%u), cm(%u), %u)",
			acp.cp_num, acp.opcode1, _arm_reg_name(acp.rd),
			acp.crn, acp.crm, acp.opcode2);
		csx_coprocessor_write(csx, &acp);
		LOG();
	}
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

	if(BTST(opcode, ARM_INST_BIT_R))
	{
		psrs = "SPSR";
		rd_v = core->spsr ? *core->spsr : 0;
	}
	else
	{
		psrs = "CPSR";
		rd_v = CPSR;
	}

	CORE_TRACE("mrs(%s, %s) /* 0x%08x */", _arm_reg_name(rd), psrs, rd_v);

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

	bit.i = BEXT(opcode, 25);
	bit.r = BEXT(opcode, 22);
	
	uint8_t field_mask = BFEXT(opcode, 19, 16);
	
	uint8_t rotate_imm, imm8;
	uint8_t rm, rm_v;
	uint8_t operand;
	
	if(bit.i)
	{
		rotate_imm = BFEXT(opcode, 11, 8);
		imm8 = BFEXT(opcode, 7, 0);
		operand = _ror(imm8, (rotate_imm << 1));
	}
	else
	{
		if(0 == BFEXT(opcode, 7, 4))
		{
			int tsbz = _check_sbz(opcode, 11, 8, &test, &result);
			if(tsbz)
				TRACE("!! sbz(opcode = 0x%08x, 11, 8, =0x%08x, =0x%08x (%u))", opcode, test, result, tsbz);

			rm = BFEXT(opcode, 3, 0);
			rm_v = csx_reg_get(core, rm);
			operand = rm_v;
		}
		else
		{
			LOG_ACTION(csx->state |= CSX_STATE_HALT);
		}
	}

	uint32_t unalloc_mask = csx_msr_unalloc_mask[arm_v5tej];
	if(0) TRACE("unalloc_mask = 0x%08x", unalloc_mask);

	if(operand & unalloc_mask)
	{
		LOG_ACTION(csx->state |= CSX_STATE_HALT);
		UNPREDICTABLE;
	}

	uint32_t byte_mask = 0;
	byte_mask |= BTST(field_mask, 0) ? (0xff << 0) : 0;
	byte_mask |= BTST(field_mask, 1) ? (0xff << 8) : 0;
	byte_mask |= BTST(field_mask, 2) ? (0xff << 16) : 0;
	byte_mask |= BTST(field_mask, 3) ? (0xff << 24) : 0;
	
	uint32_t state_mask = csx_msr_state_mask[arm_v5tej];
	uint32_t user_mask = csx_msr_user_mask[arm_v5tej];
	uint32_t priv_mask = csx_msr_priv_mask[arm_v5tej];
	
	if(0) TRACE("state_mask = 0x%08x, user_mask = 0x%08x, priv_mask = 0x%08x",
		state_mask, user_mask, priv_mask);
		
	if(0) TRACE("field_mask = 0x%08x, byte_mask = 0x%08x", field_mask, byte_mask);
	
	uint32_t saved_psr, new_psr;
	
	uint32_t mask;
	if(bit.r)
	{
		if(core->spsr)
		{
			mask = byte_mask & (user_mask | priv_mask | state_mask);
			
			saved_psr = *core->spsr;
			new_psr = (saved_psr & ~mask) | (operand & mask);
			
			if(cce)
				*core->spsr = new_psr;
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

		if(0)LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x",
			csx_reg_get(core, rSP), csx_reg_get(core, rLR), core->pc);

		if(cce)
			csx_psr_mode_switch(core, new_psr);
	}
	
	uint8_t cpsrs[5];
	cpsrs[0] = BTST(field_mask, 3) ? 'F' : 'f';
	cpsrs[1] = BTST(field_mask, 2) ? 'S' : 's';
	cpsrs[2] = BTST(field_mask, 1) ? 'X' : 'x';
	cpsrs[3] = BTST(field_mask, 0) ? 'C' : 'c';
	cpsrs[4] = 0;
	
	uint8_t cs = bit.r ? 'S' : 'C';

	csx_trace_psr(core, 0, saved_psr);

	if(bit.i)
	{
		CORE_TRACE("msr(%cPSR_%s, 0x%08x) /* 0x%08x & 0x%08x -> 0x%08x */", cs, cpsrs, operand, operand, mask, operand & mask);
	}
	else
	{
		CORE_TRACE("msr(%cPSR_%s, %s) /* 0x%08x & 0x%08x -> 0x%08x*/",
			cs, cpsrs, _arm_reg_name(rm), operand, mask, operand & mask);
	}

	if(0) LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x",
		csx_reg_get(core, rSP), csx_reg_get(core, rLR), core->pc);

	csx_trace_psr(core, 0, new_psr);
}

/* **** */

static uint8_t csx_core_arm_check_cc(csx_core_p core, uint32_t opcode)
{
	uint8_t cc = BFEXT(opcode, 31, 28);
	return(csx_core_check_cc(core, opcode, cc));
}

#define _INST0(_x0)			(((_x0) & 0x06) << 25)
#define _INST1(_x1)			(((_x1) & 0x07) << 25)

#define _INST0_i74			(_BV(7) | _BV(4))

#define _INST0_MISC0		_BV(24)
#define _INST0_MISC0_MASK	(_BF(27, 23) | _BV(20))

#define _INST0_MISC1		(_INST0_MISC0 | _INST0_i74)

void csx_core_arm_step(csx_core_p core)
{
	uint32_t pc;
	uint32_t ir = csx_reg_pc_fetch_step(core, 4, &pc);

	int thumb = pc & 1;
	if(thumb)
	{
		LOG("!! pc & 1");
		csx_reg_set(core, INSN_PC, pc);
		return;
	}

	core->csx->cycle++;

	uint8_t cce = csx_core_arm_check_cc(core, ir);

	uint8_t check0 = BFEXT(ir, 27, 25) & ~1;
	uint32_t check0_misc0 = ir & _INST0_MISC0_MASK;

	uint8_t check1 = BFEXT(ir, 27, 25);
	uint8_t	i74 = BMOV(ir, 25, 2) | BMOV(ir, 7, 1) | BEXT(ir, 4);

	uint32_t check = ir & _INST1(7);

//check1:
	switch(check)	/* check 1 */
	{
		case _INST0(0):
			if(_INST0_i74 == (ir & _INST0_i74))
				return(arm_inst_ldst(core, ir, cce));
			else if(_INST0_MISC0 != check0_misc0)
			{
				if(ARM_INST_DP == (ir & ARM_INST_DP_MASK))
					return(arm_inst_dpi(core, ir, cce));
			}
			else
			{
				if(ARM_INST_BX == (ir & ARM_INST_BX_MASK))
					return(arm_inst_bx(core, ir, cce));
				if(ARM_INST_MRS == (ir & ARM_INST_MRS_MASK))
					return(arm_inst_mrs(core, ir, cce));
				else if(ARM_INST_MSR == (ir & ARM_INST_MSR_MASK))
					return(arm_inst_msr(core, ir, cce));
			}
			break;
		case _INST1(1):
			if(ARM_INST_DP == (ir & ARM_INST_DP_MASK))
				return(arm_inst_dpi(core, ir, cce));
			break;
		case _INST1(2):
			if(ARM_INST_LDST_O11 == (ir & ARM_INST_LDST_O11_MASK))
				return(arm_inst_ldst(core, ir, cce));
			break;
		case _INST1(4):
			if(ARM_INST_LDSTM == (ir & ARM_INST_LDSTM_MASK))
				return(arm_inst_ldstm(core, ir, cce));
			break;
		case _INST1(5):
			if(ARM_INST_B == (ir & ARM_INST_B_MASK))
				return(arm_inst_b(core, ir, cce));
			break;
		case _INST1(7):
			if(ARM_INST_MCR == (ir & ARM_INST_MCR_MASK))
				return(arm_inst_mcr(core, ir, cce));
			break;
		default:
			break;
	}

//decode_fault:
	TRACE(">> ir = 0x%08x, check0 = 0x%02x, check1 = 0x%02x, i74 = 0x%02hhx",
		ir, check0, check1, i74);
	csx_core_disasm(core, pc, ir);
	LOG_ACTION(exit(1));
}
