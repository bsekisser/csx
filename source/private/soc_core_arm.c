#include "csx.h"
#include "soc_core.h"
//#include "soc_core_decode.h"
#include "soc_core_arm_inst.h"

/* **** */

static void _arm_inst_dpi_final(soc_core_p core, soc_core_dpi_p dpi)
{
	soc_core_trace_inst_dpi(core, dpi);

	if(rPC == rR(D))
	{
		if(0) {
			LOG("ip = 0x%08x, pc = 0x%08x, pc_arm = 0x%08x, pc_reg = 0x%08x",
				IP, vPC, soc_core_reg_get_pc_arm(core), soc_core_reg_get(core, rPC));

			soc_core_disasm(core, IP, IR);

			LOG_ACTION(exit(-1));
		}
		

		const int thumb = dpi->bit.s && core->spsr
			&& BTST(*core->spsr, SOC_PSR_BIT_T);

		if(thumb)
			CORE_TRACE_THUMB;
			
		CORE_TRACE_BRANCH(vR(D));
	}

	if(CCx.e)
	{
		if((rR(S) & 0x0f) == rR(S))
			core->soc->cycle++;

		if(dpi->wb)
		{
//			if(!dpi->bit.s && (rPC == rR(D))) {
			if(rPC == rR(D)) {
				soc_core_reg_set_pc_x(core, vR(D));
			} else
				soc_core_reg_set(core, rR(D), vR(D));
		}

		if(dpi->bit.s)
		{
			if(rPC == rR(D))
			{
				if(core->spsr)
					soc_core_psr_mode_switch(core, *core->spsr);
				else
					UNPREDICTABLE;
			}
			else
			{
				switch(dpi->operation)
				{
					case ARM_DPI_OPERATION_ADD:
						soc_core_flags_nzcv_add(core, vR(D), vR(N), dpi->out.v);
						break;
					case ARM_DPI_OPERATION_CMP:
					case ARM_DPI_OPERATION_SUB:
						soc_core_flags_nzcv_sub(core, vR(D), vR(N), dpi->out.v);
						break;
					default:
						soc_core_flags_nz(core, vR(D));
						BMAS(CPSR, SOC_PSR_BIT_C, dpi->out.c);
						break;
				}
			}
		}
	}
}

static void _arm_inst_dpi_operation_add(soc_core_p core, soc_core_dpi_p dpi)
{
	vR(D) = vR(N) + dpi->out.v;
}

static void _arm_inst_dpi_operation_and(soc_core_p core, soc_core_dpi_p dpi)
{
	vR(D) = vR(N) & dpi->out.v;
}

static void _arm_inst_dpi_operation_bic(soc_core_p core, soc_core_dpi_p dpi)
{
	const uint32_t nout_v = ~dpi->out.v;

	vR(D) = vR(N) & nout_v;
}

static void _arm_inst_dpi_operation_cmp(soc_core_p core, soc_core_dpi_p dpi)
{
	dpi->wb = 0;
	vR(D) = vR(N) - dpi->out.v;
}

static void _arm_inst_dpi_operation_eor(soc_core_p core, soc_core_dpi_p dpi)
{
	vR(D) = vR(N) ^ dpi->out.v;
}

static void _arm_inst_dpi_operation_mov(soc_core_p core, soc_core_dpi_p dpi)
{
	if(rR(N))
	{
		LOG("!! rn(%u) -- sbz", rR(N));
		ILLEGAL_INSTRUCTION;
	}

	vR(D) = dpi->out.v;
}

static void _arm_inst_dpi_operation_mvn(soc_core_p core, soc_core_dpi_p dpi)
{
	if(rR(N))
	{
		LOG("!! rn(%u) -- sbz", rR(N));
		ILLEGAL_INSTRUCTION;
	}

	vR(D) = ~dpi->out.v;
}

static void _arm_inst_dpi_operation_orr(soc_core_p core, soc_core_dpi_p dpi)
{
	vR(D) = vR(N) | dpi->out.v;
}

static void _arm_inst_dpi_operation_sub(soc_core_p core, soc_core_dpi_p dpi)
{
	vR(D) = vR(N) - dpi->out.v;
}

static void _arm_inst_ldstm(soc_core_p core, soc_core_ldst_p ls, soc_core_reg_t i, uint8_t user_mode_regs)
{
	uint32_t rxx_v = 0;

	/* CP15_r1_Ubit == 0 */
	const uint32_t ea = ls->ea & ~3;

	if(ls->bit.l)
	{
		rxx_v = soc_read(core->soc, ea, sizeof(uint32_t));

		if(0) LOG("r(%u)==[0x%08x](0x%08x)", i, ea, rxx_v);

		if(user_mode_regs)
			soc_core_reg_usr(core, i, &rxx_v);
		else
			soc_core_reg_set(core, i, rxx_v);
	}
	else
	{
		if(user_mode_regs)
			rxx_v = soc_core_reg_usr(core, i, 0);
		else
			rxx_v = soc_core_reg_get(core, i);
		
		if(0) LOG("[0x%08x]==r(%u)(0x%08x)", ea, i, rxx_v);

		soc_write(core->soc, ea, rxx_v, sizeof(uint32_t));
	}

	ls->ea += sizeof(uint32_t);
}

/* **** */

static void arm_inst_b(soc_core_p core)
{
	const int blx = (0x0f == mlBFEXT(IR, 31, 28));
	const int link = BEXT(IR, ARM_INST_BIT_LINK);
	const int32_t offset = mlBFEXTs(IR, 23, 0);

	if(USE_TCG) {
		const uint tcg_op = link ? tcg_inst_bl_k : tcg_inst_b_k;
		tcg_cc_i24(core, tcg_op, offset);
	} else {
		const uint32_t pc = soc_core_reg_get_pc_arm(core);

		uint32_t new_pc = pc + (offset << 2);
		
		CORE_T(const int thumb = blx);

		if(blx)
		{
			new_pc |= (link << 1) | 1;
			CORE_T(CCx.s = "AL");
			CCx.e = 1;
		}

		CORE_TRACE("b%s%s(0x%08x) /* %c(0x%08x + 0x%08x) */",
			link ? "l" : "", blx ? "x" : "", new_pc & ~1, thumb ? 'T' : 'A', pc, offset << 2);

	if(0) {
		LOG("ip = 0x%08x, pc = 0x%08x, pc_arm = 0x%08x, pc_reg = 0x%08x",
			IP, vPC, pc, soc_core_reg_get(core, rPC));

		soc_core_disasm(core, IP, IR);

		LOG_ACTION(exit(-1));
	}

		if(link) {
//			CORE_TRACE_LINK(soc_core_reg_get(core, rTEST(rPC)));
			CORE_TRACE_LINK(vPC);
		}

		CORE_TRACE_BRANCH(new_pc);

		if(CCx.e)
		{
			if(link || blx) {
//				soc_core_reg_set(core, rLR, soc_core_reg_get(core, rTEST(rPC));
				soc_core_reg_set(core, rLR, vPC);
			}

			soc_core_reg_set_pc_x(core, new_pc);
		}
	}
}

static void arm_inst_bx(soc_core_p core)
{
	soc_core_arm_decode_rm(core, 1);

	const int link = BEXT(IR, 5);
	const int thumb = vR(M) & 1; (void)thumb;

	if(USE_TCG) {
		const uint tcg_op = link ? tcg_inst_blx_k : tcg_inst_bx_k;
		tcg_cc_r0(core, tcg_op, rR(M));
	} else {
		CORE_TRACE("b%sx(r(%u)) /* %c(0x%08x) */",
			link ? "l" : "", rR(M), thumb ? 'T' : 'A', vR(M) & ~1);

	const uint pc = 0; (void)pc;
	if(0) {
		LOG("ip = 0x%08x, pc = 0x%08x, pc_arm = 0x%08x, pc_reg = 0x%08x",
			IP, vPC, pc, soc_core_reg_get(core, rPC));

		soc_core_disasm(core, IP, IR);

		LOG_ACTION(exit(-1));
	}

		if(link) {
//			CORE_TRACE_LINK(soc_core_reg_get(core, rTEST(rPC)));
			CORE_TRACE_LINK(vPC);
		}

		CORE_TRACE_BRANCH(vR(M));

		if(CCx.e)
		{
			if(link) {
				soc_core_reg_set(core, rLR, vPC);
	//			soc_core_reg_set(core, rLR, soc_core_reg_get(core, rTEST(rPC)));
			}

			soc_core_reg_set_pc_x(core, vR(M));
		}
	}
}

static void arm_inst_dpi(soc_core_p core)
{
	soc_core_dpi_t	dpi;

	soc_core_arm_decode_shifter_operand(core, &dpi);

	const int get_rn = (ARM_DPI_OPERATION_MOV != dpi.operation);
	
	soc_core_arm_decode_rn_rd(core, get_rn, 0);

	switch(dpi.operation)
	{
		case ARM_DPI_OPERATION_ADD:
			_arm_inst_dpi_operation_add(core, &dpi);
			break;
		case ARM_DPI_OPERATION_AND:
			_arm_inst_dpi_operation_and(core, &dpi);
			break;
		case ARM_DPI_OPERATION_BIC:
			_arm_inst_dpi_operation_bic(core, &dpi);
			break;
		case ARM_DPI_OPERATION_EOR:
			_arm_inst_dpi_operation_eor(core, &dpi);
			break;
		case ARM_DPI_OPERATION_CMP:
			if(dpi.bit.s)
				_arm_inst_dpi_operation_cmp(core, &dpi);
			else
				goto exit_fault;
			break;
		case ARM_DPI_OPERATION_MOV:
			_arm_inst_dpi_operation_mov(core, &dpi);
			break;
		case ARM_DPI_OPERATION_MVN:
			_arm_inst_dpi_operation_mvn(core, &dpi);
			break;
		case ARM_DPI_OPERATION_ORR:
			_arm_inst_dpi_operation_orr(core, &dpi);
			break;
		case ARM_DPI_OPERATION_SUB:
			_arm_inst_dpi_operation_sub(core, &dpi);
			break;
		default:
			goto exit_fault;
			break;
	}
	
	_arm_inst_dpi_final(core, &dpi);
	return;

exit_fault:
	LOG("operation = 0x%02x", dpi.operation);
	soc_core_disasm(core, IP, IR);
	UNIMPLIMENTED;
}

static void arm_inst_ldst(soc_core_p core)
{
	soc_core_ldst_t ls;
	soc_core_arm_decode_ldst(core, &ls);

	if(ls.bit.p)
	{
		if(ls.bit.u)
			ls.ea = vR(N) + vR(M);
		else
			ls.ea = vR(N) - vR(M);
	}
	
	if(ls.bit.l)
	{
		vR(D) = soc_read(core->soc, ls.ea, ls.rw_size);

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
		vR(D) = soc_core_reg_get(core, rR(D));
	
	soc_core_trace_inst_ldst(core, &ls);

	if(0 && ((rPC == rR(D)) || (rPC == rR(N)))) {
		LOG("ip = 0x%08x, pc = 0x%08x, pc_arm = 0x%08x, pc_reg = 0x%08x",
			IP, vPC, soc_core_reg_get_pc_arm(core), soc_core_reg_get(core, rPC));

		soc_core_disasm(core, IP, IR);

		LOG_ACTION(exit(-1));
	}

	if(ls.bit.l && (rPC == rR(D)))
		CORE_TRACE_BRANCH(vR(D));

	if(CCx.e)
	{
		if(!ls.bit.p)
		{
			if(ls.bit.u)
				ls.ea = vR(N) + vR(M);
			else
				ls.ea = vR(N) - vR(M);
		}

		if(!ls.bit.p || ls.bit.w) /* base update? */
			soc_core_reg_set(core, rR(N), ls.ea);

		if(ls.bit.l)
		{
			if(rPC == rR(D)) {
				soc_core_reg_set_pc_x(core, vR(D));
//				soc_core_reg_set(core, rTHUMB(rR(D)), vR(D));
			} else {
				soc_core_reg_set(core, rR(D), vR(D));
			}
		}
		else
		{
			if(ls.rw_size == sizeof(uint32_t))
				ls.ea &= ~3;
				
			soc_write(core->soc, ls.ea, vR(D), ls.rw_size);
		}
	}
}

static void arm_inst_ldstm(soc_core_p core)
{
	soc_core_ldst_t ls;
	soc_core_arm_decode_ldst(core, &ls);

	const uint8_t rcount = (__builtin_popcount(vR(M)) << 2);
	
	const uint32_t sp_in = vR(N);
	uint32_t sp_out = 0;
	
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
		sp_out = sp_in + rcount;
	}
	else /* decrement */
	{
		end_address = sp_in + (!ls.bit.p << 2);
		start_address = end_address - rcount;
		sp_out = sp_in - rcount;
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
	
	uint32_t rxx_v = 0;

	if(CCx.e)
	{
		for(int i = 0; i < 15; i++)
		{
			if(BTST(vR(M), i))
			{
				core->soc->cycle++;
				_arm_inst_ldstm(core, &ls, i, user_mode_regs);
			}
		}
		
		if(load_spsr && core->spsr)
			soc_core_psr_mode_switch(core, *core->spsr);

		if(BTST(vR(M), 15))
		{
			core->soc->cycle++;

			/* CP15_r1_Ubit == 0 */
			const uint32_t ea = ls.ea & ~3;

			if(ls.bit.l)
			{
				rxx_v = soc_read(core->soc, ea, sizeof(uint32_t));
				if(0) LOG("r(%u)==[0x%08x](0x%08x)", 15, ea, rxx_v);
//				soc_core_reg_set(core, rTHUMB(rPC), rxx_v);
				soc_core_reg_set_pc_x(core, rxx_v);
			}
			else
			{
//				rxx_v = soc_core_reg_get(core, rPC);
				rxx_v = soc_core_reg_get_pc_arm(core);
				if(0) LOG("[0x%08x]==r(%u)(0x%08x)", ea, 15, rxx_v);
				soc_write(core->soc, ea, rxx_v, sizeof(uint32_t));
			}

			ls.ea += sizeof(uint32_t);
		}

		if((ls.bit.w && (user_mode_regs || load_spsr))
			|| (user_mode_regs && load_spsr))
				LOG_ACTION(exit(1));

		if(ls.bit.w) 
		{
			if(0) LOG("ea = 0x%08x", ls.ea);

			assert(end_address == ls.ea);
			soc_core_reg_set(core, rR(N), sp_out);
		}
	}
}

static void arm_inst_mcr_mrc(soc_core_p core)
{
	soc_core_coproc_data_t acp;
	
	soc_core_arm_decode_coproc(core, &acp);

	soc_core_trace_inst_mcr(core, &acp);

	if(acp.bit.l)
		soc_core_coprocessor_read(core, &acp);
	else
		soc_core_coprocessor_write(core, &acp);
}

static void arm_inst_mrs(soc_core_p core)
{
	uint32_t test = 0, result = 0;

	const int tsbo = _check_sbo(IR, 19, 16, &test, &result);
	if(tsbo)
		TRACE("!! sbo(opcode = 0x%08x, 19, 16, =0x%08x, =0x%08x (%u))", IR, test, result, tsbo);

	const int tsbz = _check_sbz(IR, 11, 0, &test, &result);
	if(tsbz)
		TRACE("!! sbz(opcode = 0x%08x, 11, 0, =0x%08x, =0x%08x (%u))", IR, test, result, tsbz);

	if(tsbo || tsbz)
		UNPREDICTABLE;

	soc_core_arm_decode_rd(core, 0);

	const char* psrs = ""; (void)psrs;

	if(BTST(IR, ARM_INST_BIT_R))
	{
		CORE_T(psrs = "SPSR");
		vR(D) = core->spsr ? *core->spsr : 0;
	}
	else
	{
		CORE_T(psrs = "CPSR");
		vR(D) = CPSR;
	}

	CORE_TRACE("mrs(%s, %s) /* 0x%08x */", _arm_reg_name(rR(D)), psrs, vR(D));

	if(CCx.e)
		soc_core_reg_set(core, rR(D), vR(D));
}

static const uint32_t soc_core_msr_priv_mask[] = 
	{ 0x0000000f, 0x0000000f, 0x0000000f, 0x0000000f, 0x000001df };
static const uint32_t soc_core_msr_state_mask[] = 
	{ 0x00000000, 0x00000020, 0x00000020, 0x01000020, 0x01000020 };
static const uint32_t soc_core_msr_unalloc_mask[] = 
	{ 0x0fffff20, 0x0fffff00, 0x07ffff00, 0x06ffff00, 0x06f0fc00 };
static const uint32_t soc_core_msr_user_mask[] = 
	{ 0xf0000000, 0xf0000000, 0xf8000000, 0xf8000000, 0xf80f0200 };

static void arm_inst_msr(soc_core_p core)
{
	uint32_t test = 0, result = 0;

	const int tsbo = _check_sbo(IR, 15, 12, &test, &result);
	if(tsbo) {
		TRACE("!! sbo(opcode = 0x%08x, 15, 12, =0x%08x, =0x%08x (%u))", IR, test, result, tsbo);
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
				TRACE("!! sbz(opcode = 0x%08x, 11, 8, =0x%08x, =0x%08x (%u))", IR, test, result, tsbz);
				UNPREDICTABLE;
			}

			rR(M) = mlBFEXT(IR, 3, 0);
			vR(M) = soc_core_reg_get(core, rR(M));
			operand = vR(M);
		}
		else
		{
			soc_core_disasm(core, IP, IR);
			UNIMPLIMENTED;
		}
	}

	const uint32_t unalloc_mask = soc_core_msr_unalloc_mask[arm_v5tej];
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
	
	const uint32_t state_mask = soc_core_msr_state_mask[arm_v5tej];
	const uint32_t user_mask = soc_core_msr_user_mask[arm_v5tej];
	const uint32_t priv_mask = soc_core_msr_priv_mask[arm_v5tej];
	
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
			
			if(CCx.e)
				*core->spsr = new_psr;
		}
		else
		{
			UNPREDICTABLE;
		}
	}
	else
	{
		if(soc_core_in_a_privaleged_mode(core))
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

		if(0)LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x",
			soc_core_reg_get(core, rSP), soc_core_reg_get(core, rLR), IP);

		if(BTST(saved_psr, SOC_PSR_BIT_T) != BTST(new_psr, SOC_PSR_BIT_T))
			CORE_TRACE_THUMB;

		if(CCx.e)
			soc_core_psr_mode_switch(core, new_psr);
	}
	
	uint8_t cpsrs[5]; (void)cpsrs;
	cpsrs[0] = BTST(field_mask, 3) ? 'F' : 'f';
	cpsrs[1] = BTST(field_mask, 2) ? 'S' : 's';
	cpsrs[2] = BTST(field_mask, 1) ? 'X' : 'x';
	cpsrs[3] = BTST(field_mask, 0) ? 'C' : 'c';
	cpsrs[4] = 0;

	const uint8_t cs = bit_r ? 'S' : 'C'; (void)cs;

	soc_core_trace_psr(core, 0, saved_psr);

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

	if(0) LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x",
		soc_core_reg_get(core, rSP), soc_core_reg_get(core, rLR), IP);

	soc_core_trace_psr(core, 0, new_psr);
}

/* **** */

static uint8_t soc_core_arm_check_cc(soc_core_p core, uint32_t opcode)
{
	const uint8_t cc = mlBFEXT(opcode, 31, 28);
	return(soc_core_check_cc(core, opcode, cc));
}

#define _INST0_MISC0		_BV(24)
#define _INST0_MISC0_MASK	(mlBF(27, 23) | _BV(20))
#define _INST0_i74			(_BV(7) | _BV(4))

#define _INST1(_x1)			(((_x1) & 0x07) << 25)

void soc_core_arm_step(soc_core_p core)
{
	const soc_p soc = core->soc;

	IR = soc_core_reg_pc_fetch_step_arm(core);

	CCx.e = soc_core_arm_check_cc(core, IR);
	if(!CCx.e && (0x0f == mlBFEXT(IR, 31, 28)))
	{
		if(ARM_INST_B == (IR & ARM_INST_B_MASK))
			return(arm_inst_b(core));
		goto decode_fault;
	}

	const uint32_t check = IR & _INST1(7);

	switch(check) {
		case _INST1(0): /* xxxx 000x xxxx xxxx */
			if(_INST0_i74 == (IR & _INST0_i74))
				return(arm_inst_ldst(core));
			else if(_INST0_MISC0 != (IR & _INST0_MISC0_MASK))
			{
				if(ARM_INST_DP == (IR & ARM_INST_DP_MASK))
					return(arm_inst_dpi(core));
			}
			else
			{
				if(ARM_INST_BX == (IR & ARM_INST_BX_MASK))
					return(arm_inst_bx(core));
				if(ARM_INST_MRS == (IR & ARM_INST_MRS_MASK))
					return(arm_inst_mrs(core));
				if((ARM_INST_MSR_I == (IR & ARM_INST_MSR_I_MASK))
					|| (ARM_INST_MSR_R == (IR & ARM_INST_MSR_R_MASK)))
						return(arm_inst_msr(core));
			}
			break;
		case _INST1(1): /* xxxx 001x xxxx xxxx */
			if((mlBF(25, 24) | _BV(21)) == (IR & (mlBF(27, 23) | mlBF(21, 20))))
				;
			else if(ARM_INST_DP == (IR & ARM_INST_DP_MASK))
				return(arm_inst_dpi(core));
			break;
		case _INST1(2): /* xxxx 010x xxxx xxxx */
			if(ARM_INST_LDST_O11 == (IR & ARM_INST_LDST_O11_MASK))
				return(arm_inst_ldst(core));
			break;
		case _INST1(4): /* xxxx 100x xxxx xxxx */
			if(ARM_INST_LDSTM == (IR & ARM_INST_LDSTM_MASK))
				return(arm_inst_ldstm(core));
			break;
		case _INST1(5):	/* xxxx 101x xxxx xxxx */
			if(ARM_INST_B == (IR & ARM_INST_B_MASK))
				return(arm_inst_b(core));
			break;
		case _INST1(7): /* xxxx 111x xxxx xxxx */
			if(ARM_INST_MCR_MRC == (IR & ARM_INST_MCR_MRC_MASK))
				return(arm_inst_mcr_mrc(core));
			break;
	}

decode_fault: ;
	const uint32_t check1 = mlBFEXT(IR, 27, 25); (void)check1;
	const uint32_t check0 = check1 & ~1; (void) check0;

	CORE_TRACE("check0 = 0x%02x, check1 = 0x%02x", check0, check1);
	soc_core_disasm(core, IP, IR);
	UNIMPLIMENTED;

	SOC_STATE_SET(HALT);
}
