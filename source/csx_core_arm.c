#include <assert.h>

#include "csx.h"
#include "csx_core.h"
#include "csx_core_utility.h"

#include "csx_core_arm_decode.h"
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

static void arm_inst_dpi_final(csx_core_p core, csx_dpi_p dpi, uint8_t cce)
{
	csx_trace_inst_dpi(core, dpi, cce);

	if(rPC == rR(D))
	{
		const int thumb = dpi->bit.s && core->spsr
			&& BTST(*core->spsr, CSX_PSR_BIT_T);

		if(thumb)
			CORE_TRACE_THUMB;
			
		CORE_TRACE_BRANCH(vR(D));
	}

	if(cce)
	{
		if((rR(S) & 0x0f) == rR(S))
			CYCLE++;

		if(dpi->bit.s)
		{
			if(rPC == rR(D))
			{
				if(core->spsr)
					csx_psr_mode_switch(core, *core->spsr);
				else
					UNPREDICTABLE;
			}
			else
			{
				switch(dpi->operation)
				{
					case ARM_DPI_OPERATION_ADD:
						csx_core_flags_nzcv_add(core, vR(D), vR(N), dpi->out.v);
						break;
					case ARM_DPI_OPERATION_CMP:
					case ARM_DPI_OPERATION_SUB:
						csx_core_flags_nzcv_sub(core, vR(D), vR(N), dpi->out.v);
						break;
					default:
						csx_core_flags_nz(core, vR(D));
						BMAS(CPSR, CSX_PSR_BIT_C, dpi->out.c);
						break;
				}
			}
		}
		if(dpi->wb)
		{
			if(!dpi->bit.s && (rPC == rR(D)))
				csx_reg_set_pcx(core, vR(D));
			else
				csx_reg_set(core, rR(D), vR(D));
		}
	}
}

static void arm_inst_dpi_operation_add(csx_core_p core, csx_dpi_p dpi)
{
	vR(D) = vR(N) + dpi->out.v;

	dpi->mnemonic = "add";
	snprintf(dpi->op_string, 255,
		"/* 0x%08x + 0x%08x --> 0x%08x */",
		vR(N), dpi->out.v, vR(D));
}

static void arm_inst_dpi_operation_and(csx_core_p core, csx_dpi_p dpi)
{
	vR(D) = vR(N) & dpi->out.v;

	dpi->mnemonic = "and";

	snprintf(dpi->op_string, 255,
		"/* 0x%08x & 0x%08x --> 0x%08x */",
		vR(N), dpi->out.v, vR(D));
}

static void arm_inst_dpi_operation_bic(csx_core_p core, csx_dpi_p dpi)
{
	uint32_t nout_v = ~dpi->out.v;
	vR(D) = vR(N) & nout_v;

	dpi->mnemonic = "bic";

	snprintf(dpi->op_string, 255,
		"/* 0x%08x & !0x%08x(0x%08x) --> 0x%08x */",
		vR(N), dpi->out.v, nout_v, vR(D));
}

static void arm_inst_dpi_operation_cmp(csx_core_p core, csx_dpi_p dpi)
{
	dpi->wb = 0;
	vR(D) = vR(N) - dpi->out.v;

	dpi->mnemonic = "cmp";

	snprintf(dpi->op_string, 255,
		"/* 0x%08x - 0x%08x ??? 0x%08x */",
		vR(N), dpi->out.v, vR(D));
}

static void arm_inst_dpi_operation_eor(csx_core_p core, csx_dpi_p dpi)
{
	vR(D) = vR(N) ^ dpi->out.v;

	dpi->mnemonic = "eor";

	snprintf(dpi->op_string, 255,
		"/* 0x%08x ^ 0x%08x --> 0x%08x */",
		vR(N), dpi->out.v, vR(D));
}

static void arm_inst_dpi_operation_mov(csx_core_p core, csx_dpi_p dpi)
{
	if(rR(N))
	{
		LOG("!! rn(%u) -- sbz", rR(N));
		ILLEGAL_INSTRUCTION;
	}

	rR(N) = ~0;
	vR(D) = dpi->out.v;

	dpi->mnemonic = "mov";
	
	if(!dpi->bit.i && (rR(D) == rR(M)))
		snprintf(dpi->op_string, 255, "/* nop */");
	else
		snprintf(dpi->op_string, 255, "/* 0x%08x */", vR(D));
}

static void arm_inst_dpi_operation_mvn(csx_core_p core, csx_dpi_p dpi)
{
	if(rR(N))
	{
		LOG("!! rn(%u) -- sbz", rR(N));
		ILLEGAL_INSTRUCTION;
	}

	rR(N) = ~0;
	vR(D) = ~dpi->out.v;

	dpi->mnemonic = "mvn";
	snprintf(dpi->op_string, 255, "/* 0x%08x */", vR(D));
}

static void arm_inst_dpi_operation_orr(csx_core_p core, csx_dpi_p dpi)
{
	vR(D) = vR(N) | dpi->out.v;

	dpi->mnemonic = "orr";
	snprintf(dpi->op_string, 255,
		"/* 0x%08x | 0x%08x --> 0x%08x */",
		vR(N), dpi->out.v, vR(D));
}

static void arm_inst_dpi_operation_sub(csx_core_p core, csx_dpi_p dpi)
{
	vR(D) = vR(N) - dpi->out.v;

	dpi->mnemonic = "sub";
	snprintf(dpi->op_string, 255,
		"/* 0x%08x - 0x%08x --> 0x%08x */",
		vR(N), dpi->out.v, vR(D));
}

static void arm_inst_dpi(csx_core_p core, uint8_t cce)
{
	csx_dpi_t	dpi;

	csx_core_arm_decode_shifter_operand(core, &dpi);

	const int get_rn = (ARM_DPI_OPERATION_MOV != dpi.operation);

	csx_core_arm_decode_rn_rd(core, get_rn, 0);

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
		case ARM_DPI_OPERATION_EOR:
			arm_inst_dpi_operation_eor(core, &dpi);
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
	
	arm_inst_dpi_final(core, &dpi, cce);
	return;

exit_fault:
	LOG("operation = 0x%02x", dpi.operation);
	csx_core_disasm(core, IP, IR);
	UNIMPLIMENTED;
}


static void arm_inst_b(csx_core_p core, uint8_t cce)
{
	const int blx = (0x0f == mlBFEXT(IR, 31, 28));
	const int hl = BEXT(IR, ARM_INST_BIT_LINK);
	const int32_t offset = mlBFEXTs(IR, 23, 0);

	const int link = blx || (!blx && hl);
	uint32_t new_pc = PC_ARM + (offset << 2);
	
	if(blx)
	{
		new_pc |= (hl << 1) | 1;
		CORE_T(core->ccs = "AL");
		cce = 1;
	}

	CORE_TRACE("b%s%s(0x%08x) /* %c(0x%08x) hl = %01u */",
		link ? "l" : "", blx ? "x" : "", new_pc & ~1, new_pc & 1 ? 'T' : 'A', offset, hl);

	if(link)
		CORE_TRACE_LINK(PC);
	
	CORE_TRACE_BRANCH(new_pc);

	if(cce)
	{
		if(link)
			LR = PC;

		csx_reg_set_pcx(core, new_pc);
	}
}

static void arm_inst_bx(csx_core_p core, uint8_t cce)
{
	csx_core_arm_decode_rm(core, 1);
	
	const int link = BEXT(IR, 5);

	const uint32_t new_pc = vR(M);
	const int thumb = new_pc & 1;

	CORE_TRACE("b%sx(r(%u)) /* %c(0x%08x) */",
		link ? "l" : "", rR(M), thumb ? 'T' : 'A', new_pc & ~1);

	if(link)
		CORE_TRACE_LINK(PC);

	CORE_TRACE_BRANCH(new_pc);

	if(cce)
	{
		if(link)
			LR = PC;

		csx_reg_set_pcx(core, new_pc);
	}
}

static void arm_inst_ldst(csx_core_p core, uint8_t cce)
{
	csx_ldst_t ls;
	csx_core_arm_decode_ldst(core, &ls);

	if(ls.bit.p)
	{
		if(ls.bit.u)
			ls.ea += vR(M);
		else
			ls.ea -= vR(M);
	}
	
	if(ls.bit.l)
	{
		vR(D) = csx_core_read(core, ls.ea, ls.rw_size);

		/*	ARMv5, CP15_r1_Ubit == 0 */
		if(ls.rw_size == sizeof(uint32_t))
		{
			assert(0 == (ls.ea & 3));
			vR(D) = _ror(vR(D), ((ls.ea & 3) << 3));
		}

		if(ls.flags.s) /* sign extend ? */
			vR(D) = mlBFEXTs(vR(D), (8 << (ls.rw_size >> 1)), 0);
	}
	else
		vR(D) = csx_reg_get(core, rR(D));
	
	csx_trace_inst_ldst(core, &ls, cce);

	if(ls.bit.l && (rPC == rR(D)))
		CORE_TRACE_BRANCH(vR(D));

	if(cce)
	{
		if(!ls.bit.p)
		{
			ls.ea = vR(N);
			
			if(ls.bit.u)
				ls.ea += vR(M);
			else
				ls.ea -= vR(M);
		}

		if(!ls.bit.p || ls.bit.w) /* base update? */
			csx_reg_set(core, rR(N), ls.ea);

		if(ls.bit.l)
		{
			if(rPC == rR(D))
				csx_reg_set_pcx(core, vR(D));
			else
				csx_reg_set(core, rR(D), vR(D));
		}
		else
		{
			if(ls.rw_size == sizeof(uint32_t))
				ls.ea &= ~3;
				
			csx_core_write(core, ls.ea, vR(D), ls.rw_size);
		}
	}
}

static void _arm_inst_ldstm(csx_core_p core, csx_ldst_p ls, csx_reg_t i, uint8_t user_mode_regs)
{
	uint32_t rxx_v = 0;

	/* CP15_r1_Ubit == 0 */
	const uint32_t ea = ls->ea & ~3;

	if(ls->bit.l)
	{
		rxx_v = csx_core_read(core, ea, sizeof(uint32_t));

		if(0) LOG("r(%u)==[0x%08x](0x%08x)", i, ea, rxx_v);

		if(user_mode_regs)
			csx_reg_usr(core, i, &rxx_v);
		else
			csx_reg_set(core, i, rxx_v);
	}
	else
	{
		if(user_mode_regs)
			rxx_v = csx_reg_usr(core, i, 0);
		else
			rxx_v = csx_reg_get(core, i);
		
		if(0) LOG("[0x%08x]==r(%u)(0x%08x)", ea, i, rxx_v);

		csx_core_write(core, ea, rxx_v, sizeof(uint32_t));
	}

	ls->ea += sizeof(uint32_t);
}

static void arm_inst_ldstm(csx_core_p core, uint8_t cce)
{
	csx_ldst_t ls;
	csx_core_arm_decode_ldst(core, &ls);

	const uint8_t rcount = (__builtin_popcount(vR(M)) << 2);
	
	const uint32_t sp_in = vR(N);
	uint32_t sp_out = sp_in;
	
	/*
	 * DA	!ls.bit.u && !ls.bit.p
	 * DB	!ls.bit.u && ls.bit.p
	 * IA	ls.bit.u && !ls.bit.p
	 * IB	ls.bit.u && ls.bit.p
	 * 
	 */

	uint32_t start_address = 0;
	uint32_t end_address = 0;

	if(ls.bit.u) /* increment */
	{
		start_address = sp_in + (ls.bit.p << 2);
		end_address = start_address + rcount;
		sp_out += rcount;
	}
	else /* decrement */
	{
		end_address = sp_in + (!ls.bit.p << 2);
		start_address = end_address - rcount;
		sp_out -= rcount;
	}

	if(0) LOG("sp_in = 0x%08x, start_address = 0x%08x, end_address = 0x%08x",
		sp_in, start_address, end_address);
	if(0) LOG("sp_out = 0x%08x", sp_out);

	const char *opstr; (void)opstr;
	if(0 && rSP == rR(N))
		opstr = ls.bit.l ? "pop" : "push";
	else
		opstr = ls.bit.l ? "ldm" : "stm";

	char reglist[17]; (void)reglist;
	for(int i = 0; i <= 15; i++)
	{
		uint8_t c = (i > 9 ? ('a' + (i - 10)) : '0' + i);
		reglist[i] = BTST(vR(M), i) ? c : '.';
	}
	reglist[16] = 0;
	
	const int load_spsr = ls.bit.s22 && ls.bit.l && BTST(vR(M), 15);

	const int user_mode_regs_load = ls.bit.s22 && ls.bit.l && !ls.bit.w && !BTST(vR(M), 15);
	const int user_mode_regs_store = ls.bit.s22 && !ls.bit.l;

	if(0) LOG("s = %01u, umrl = %01u, umrs = %01u", ls.bit.s22, user_mode_regs_load, user_mode_regs_store);

	const int user_mode_regs = user_mode_regs_load || user_mode_regs_store;

	CORE_TRACE("%s%c%c(r(%u)%s, {%s}%s%s) /* 0x%08x */" ,
		opstr, ls.bit.u ? 'i' : 'd', ls.bit.p ? 'b' : 'a',
		rR(N), ls.bit.w ? "!" : "", reglist,
		user_mode_regs ? ", USER" : "",
		load_spsr ? ", SPSR" : "", sp_in);
	
	ls.ea = start_address;

	/* CP15_r1_Ubit == 0 */
	assert(0 == (ls.ea & 3));
//	ls.ea &= ~3;
	
	if(cce)
	{
		for(int i = 0; i <= 15; i++)
		{
			if(BTST(vR(M), i))
			{
				CYCLE++;
				_arm_inst_ldstm(core, &ls, i, user_mode_regs);
			}
		}
		
		if(load_spsr && core->spsr)
			csx_psr_mode_switch(core, *core->spsr);

		if((ls.bit.w && (user_mode_regs || load_spsr))
			|| (user_mode_regs && load_spsr))
				LOG_ACTION(exit(1));

		if(ls.bit.w) 
		{
			if(0) LOG("ea = 0x%08x", ls.ea);

			assert(end_address == ls.ea);
			csx_reg_set(core, rR(N), sp_out);
		}
	}
}

static void arm_inst_mcr(csx_core_p core, uint8_t cce)
{
	csx_p csx = core->csx;
	csx_coproc_data_t acp;
	
	csx_core_arm_decode_coproc(core, &acp);

	if(acp.bit.l)
	{
		csx_coprocessor_read(csx, &acp);
		CORE_TRACE("mrc(p(%u), %u, %s, %s, %s, %u)",
			acp.cp_num, acp.opcode1, _arm_reg_name(rR(D)),
			_arm_creg_name(rR(N)), _arm_creg_name(rR(M)),
			acp.opcode2);

		LOG_ACTION(exit(1));
	}
	else
	{
		CORE_TRACE("mcr(p(%u), %u, %s, %s, %s, %u)",
			acp.cp_num, acp.opcode1, _arm_reg_name(rR(D)),
			_arm_creg_name(rR(N)), _arm_creg_name(rR(M)),
			acp.opcode2);
		csx_coprocessor_write(csx, &acp);
	}
}

static void arm_inst_mrs(csx_core_p core, uint8_t cce)
{
	uint32_t test = 0, result = 0;

	const int tsbo = _check_sbo(IR, 19, 16, &test, &result);
	if(tsbo)
		TRACE("!! sbo(opcode = 0x%08x, 19, 16, =0x%08x, =0x%08x (%u))", test, result, tsbo);

	const int tsbz = _check_sbz(IR, 11, 0, &test, &result);
	if(tsbz)
		TRACE("!! sbz(opcode = 0x%08x, 11, 0, =0x%08x, =0x%08x (%u))", test, result, tsbz);

	if(tsbo || tsbz)
		UNPREDICTABLE;

	csx_core_arm_decode_rd(core, 0);

	const char* psrs = "";

	if(BTST(IR, ARM_INST_BIT_R))
	{
		psrs = "SPSR";
		vR(D) = core->spsr ? *core->spsr : 0;
	}
	else
	{
		psrs = "CPSR";
		vR(D) = CPSR;
	}

	CORE_TRACE("mrs(%s, %s) /* 0x%08x */", _arm_reg_name(rR(D)), psrs, vR(D));

	if(cce)
		csx_reg_set(core, rR(D), vR(D));
}

static const uint32_t csx_msr_priv_mask[] = 
	{ 0x0000000f, 0x0000000f, 0x0000000f, 0x0000000f, 0x000001df };
static const uint32_t csx_msr_state_mask[] = 
	{ 0x00000000, 0x00000020, 0x00000020, 0x01000020, 0x01000020 };
static const uint32_t csx_msr_unalloc_mask[] = 
	{ 0x0fffff20, 0x0fffff00, 0x07ffff00, 0x06ffff00, 0x06f0fc00 };
static const uint32_t csx_msr_user_mask[] = 
	{ 0xf0000000, 0xf0000000, 0xf8000000, 0xf8000000, 0xf80f0200 };

static void arm_inst_msr(csx_core_p core, uint8_t cce)
{
	csx_p csx = core->csx; (void)csx;
	
	uint32_t test = 0, result = 0;

	const int tsbo = _check_sbo(IR, 15, 12, &test, &result);
	if(tsbo) {
		TRACE("!! sbo(opcode = 0x%08x, 15, 12, =0x%08x, =0x%08x (%u))", test, result, tsbo);
		UNPREDICTABLE;
	}

//	struct {
		const int bit_i = BEXT(IR, 25);
		const int bit_r = BEXT(IR, 22);
//	}bit;
	
	const uint8_t field_mask = mlBFEXT(IR, 19, 16);
	
	uint8_t rotate_imm = 0, imm8 = 0;
	uint8_t operand = 0;
	
	if(bit_i)
	{
		rotate_imm = mlBFEXT(IR, 11, 8);
		imm8 = mlBFEXT(IR, 7, 0);
		operand = _ror(imm8, (rotate_imm << 1));
	}
	else
	{
		if(0 == mlBFEXT(IR, 7, 4))
		{
			const int tsbz = _check_sbz(IR, 11, 8, &test, &result);
			if(tsbz)
			{
				TRACE("!! sbz(opcode = 0x%08x, 11, 8, =0x%08x, =0x%08x (%u))", test, result, tsbz);
				UNPREDICTABLE;
			}

			csx_core_arm_decode_rm(core, 1);
			operand = vR(M);
		}
		else
		{
			UNIMPLIMENTED;
		}
	}

	uint32_t unalloc_mask = csx_msr_unalloc_mask[arm_v5tej];
	if(0) TRACE("unalloc_mask = 0x%08x", unalloc_mask);

	if(operand & unalloc_mask)
	{
		UNPREDICTABLE;
	}

	uint32_t byte_mask = 0;
	byte_mask |= BTST(field_mask, 0) ? (0xff << 0) : 0;
	byte_mask |= BTST(field_mask, 1) ? (0xff << 8) : 0;
	byte_mask |= BTST(field_mask, 2) ? (0xff << 16) : 0;
	byte_mask |= BTST(field_mask, 3) ? (0xff << 24) : 0;
	
	const uint32_t state_mask = csx_msr_state_mask[arm_v5tej];
	const uint32_t user_mask = csx_msr_user_mask[arm_v5tej];
	const uint32_t priv_mask = csx_msr_priv_mask[arm_v5tej];
	
	if(0) TRACE("state_mask = 0x%08x, user_mask = 0x%08x, priv_mask = 0x%08x",
		state_mask, user_mask, priv_mask);
		
	if(0) TRACE("field_mask = 0x%08x, byte_mask = 0x%08x", field_mask, byte_mask);
	
	uint32_t saved_psr = 0, new_psr = 0;
	
	uint32_t mask = 0;
	if(bit_r)
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
			UNPREDICTABLE;
		}
	}
	else
	{
		if(csx_in_a_privaleged_mode(core))
		{
			if(operand & state_mask)
			{
				UNPREDICTABLE;
			}
			else
				mask = byte_mask & (user_mask | priv_mask);
		}
		else
			mask = byte_mask & user_mask;

		saved_psr = CPSR;
		new_psr = (saved_psr & ~mask) | (operand & mask);

		if(0) LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x", SP, LR, IP);

		if(BTST(saved_psr, CSX_PSR_BIT_T) != BTST(new_psr, CSX_PSR_BIT_T))
			CORE_TRACE_THUMB;

		if(cce)
			csx_psr_mode_switch(core, new_psr);
	}
	
	uint8_t cpsrs[5];
	cpsrs[0] = BTST(field_mask, 3) ? 'F' : 'f';
	cpsrs[1] = BTST(field_mask, 2) ? 'S' : 's';
	cpsrs[2] = BTST(field_mask, 1) ? 'X' : 'x';
	cpsrs[3] = BTST(field_mask, 0) ? 'C' : 'c';
	cpsrs[4] = 0;
	
	const uint8_t cs = bit_r ? 'S' : 'C';

	csx_trace_psr(core, 0, saved_psr);

	if(bit_i)
	{
		CORE_TRACE("msr(%cPSR_%s, 0x%08x) /* 0x%08x & 0x%08x -> 0x%08x */",
			cs, cpsrs, operand, operand, mask, operand & mask);
	}
	else
	{
		CORE_TRACE("msr(%cPSR_%s, %s) /* 0x%08x & 0x%08x -> 0x%08x*/",
			cs, cpsrs, _arm_reg_name(rR(M)), operand, mask, operand & mask);
	}

	if(0) LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x", SP, LR, IP);

	csx_trace_psr(core, 0, new_psr);
}

/* **** */

static uint8_t csx_core_arm_check_cc(csx_core_p core)
{
	const uint8_t cc = mlBFEXT(IR, 31, 28);
	return(csx_core_check_cc(core, cc));
}

#define _INST0(_x0)			(((_x0) & 0x06) << 25)
#define _INST1(_x1)			(((_x1) & 0x07) << 25)

#define _INST0_i74			(_BV(7) | _BV(4))

#define _INST0_MISC0		_BV(24)
#define _INST0_MISC0_MASK	(mlBF(27, 23) | _BV(20))

#define _INST0_MISC1		(_INST0_MISC0 | _INST0_i74)

void csx_core_arm_step(csx_core_p core)
{
	IR = csx_reg_pc_fetch_step_arm(core);

	const int thumb = PC & 1;
	if(thumb)
	{
		LOG("!! pc & 1");
		csx_reg_set_pcx(core, PC);
		return;
	}

	const uint8_t cce = csx_core_arm_check_cc(core);
	if(!cce && (0x0f == mlBFEXT(IR, 31, 28)))
	{
		if(ARM_INST_B == (IR & ARM_INST_B_MASK))
			return(arm_inst_b(core, cce));
		goto decode_fault;
	}

	uint8_t check0 = mlBFEXT(IR, 27, 25) & ~1;
	uint32_t check0_misc0 = IR & _INST0_MISC0_MASK;

	uint8_t check1 = mlBFEXT(IR, 27, 25);
	const uint8_t	i74 = BMOV(IR, 25, 2) | BMOV(IR, 7, 1) | BEXT(IR, 4);

	uint32_t check = IR & _INST1(7);

//check1:
	switch(check)	/* check 1 */
	{
		case _INST1(0): /* xxxx 000x xxxx xxxx */
			if(_INST0_i74 == (IR & _INST0_i74))
				return(arm_inst_ldst(core, cce));
			else if(_INST0_MISC0 != check0_misc0)
			{
				if(ARM_INST_DP == (IR & ARM_INST_DP_MASK))
					return(arm_inst_dpi(core, cce));
			}
			else
			{
				if(ARM_INST_BX == (IR & ARM_INST_BX_MASK))
					return(arm_inst_bx(core, cce));
				if(ARM_INST_MRS == (IR & ARM_INST_MRS_MASK))
					return(arm_inst_mrs(core, cce));
				else if(ARM_INST_MSR == (IR & ARM_INST_MSR_MASK))
					return(arm_inst_msr(core, cce));
			}
			break;
		case _INST1(1): /* xxxx 001x xxxx xxxx */
			if((mlBF(25, 24) | _BV(21)) == (IR & (mlBF(27, 23) | mlBF(21, 20))))
				;
			else if(ARM_INST_DP == (IR & ARM_INST_DP_MASK))
				return(arm_inst_dpi(core, cce));
			break;
		case _INST1(2): /* xxxx 010x xxxx xxxx */
			if(ARM_INST_LDST_O11 == (IR & ARM_INST_LDST_O11_MASK))
				return(arm_inst_ldst(core, cce));
			break;
		case _INST1(4): /* xxxx 100x xxxx xxxx */
			if(ARM_INST_LDSTM == (IR & ARM_INST_LDSTM_MASK))
				return(arm_inst_ldstm(core, cce));
			break;
		case _INST1(5): /* xxxx 101x xxxx xxxx */
			if(ARM_INST_B == (IR & ARM_INST_B_MASK))
				return(arm_inst_b(core, cce));
			break;
		case _INST1(7): /* xxxx 111x xxxx xxxx */
			if(ARM_INST_MCR == (IR & ARM_INST_MCR_MASK))
				return(arm_inst_mcr(core, cce));
			break;
		default:
			break;
	}

decode_fault:
	TRACE(">> ir = 0x%08x, check0 = 0x%02x, check1 = 0x%02x, i74 = 0x%02hhx",
		IR, check0, check1, i74);
	csx_core_disasm(core, PC, IR);
	UNIMPLIMENTED;
	(void)check0;
	(void)check1;
	(void)i74;
}
