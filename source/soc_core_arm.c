#define ARM_IP_NEXT ((IP + 4) & ~3U)
#define ARM_PC ((IP + 8) & ~3U)

#define rRvRvPC ARM_PC


/* **** */

#include "soc_core_arm.h"
#include "soc_core_arm_decode.h"
#include "soc_core_arm_inst.h"

#include "soc_core_disasm.h"
#include "soc_core_ldst.h"
#include "soc_core_psr.h"
#include "soc_core_shifter.h"
#include "soc_core_strings.h"
#include "soc_core_trace.h"
#include "soc_core_trace_arm.h"
#include "soc_core_utility.h"

/* **** */

#include "csx_cp15_reg1.h"
#include "csx_soc_exception.h"
#include "csx_statistics.h"

/* **** */

#include "bitfield.h"
#include "log.h"
#include "shift_roll.h"

#define likely(_x) __builtin_expect(!!(_x), 1)
#define unlikely(_x) __builtin_expect(!!(_x), 0)


/* **** */

//#define _CHECK_PEDANTIC_INST_SBZ_
#include "alubox_arm.h"

static alubox_fn _alubox_dpi_no_wb_fn[16] = {
	_alubox_arm_and,	_alubox_arm_eor,	_alubox_arm_sub,	_alubox_arm_rsb,
	_alubox_arm_add,	_alubox_arm_adc,	_alubox_arm_sbc,	_alubox_arm_rsc,
	_alubox_arm_and,	_alubox_arm_eor,	_alubox_arm_sub,	_alubox_arm_add,
	_alubox_arm_orr,	_alubox_arm_mov,	_alubox_arm_bic,	_alubox_arm_mvn,
};

static alubox_fn _alubox_dpi_fn[32] = {
	_alubox_arm_and_wb,	_alubox_arm_ands,	_alubox_arm_eor_wb,	_alubox_arm_eors,
	_alubox_arm_sub_wb,	_alubox_arm_subs,	_alubox_arm_rsb_wb,	_alubox_arm_rsbs,
	_alubox_arm_add_wb,	_alubox_arm_adds,	_alubox_arm_adc_wb,	_alubox_arm_adcs,
	_alubox_arm_sbc_wb,	_alubox_arm_sbcs,	_alubox_arm_rsc_wb,	_alubox_arm_rscs,
	_alubox_arm_nop_xx,	_alubox_arm_tsts,	_alubox_arm_nop_xx,	_alubox_arm_teqs,
	_alubox_arm_nop_xx,	_alubox_arm_cmps,	_alubox_arm_nop_xx,	_alubox_arm_cmns,
	_alubox_arm_orr_wb,	_alubox_arm_orrs,	_alubox_arm_mov_wb,	_alubox_arm_movs,
	_alubox_arm_bic_wb,	_alubox_arm_bics,	_alubox_arm_mvn_wb,	_alubox_arm_mvns,
};

/* **** */

static void _arm_inst_dpi_final(soc_core_p core)
{
	soc_core_trace_inst_dpi(core);

	const unsigned is_r_pc = (rPC == rR(D));

	if(likely(CCx.e))
	{
		if(0 != DPI_WB) {
			if(is_r_pc) {
				if(DPI_BIT(s20)) {
					if(core->spsr) {
						soc_core_psr_mode_switch(core, *core->spsr);
					} else
						UNPREDICTABLE;
				}

				soc_core_reg_set_thumb(core, IF_CPSR_C(32) ? PC & 1 : 0);
			}
		}
	}
}

static void _arm_inst_dp(soc_core_p core)
{
	if(_check_pedantic_arm_decode_fault) {
		if(ARM_INST_DP != (IR & ARM_INST_DP_MASK))
			DECODE_FAULT;
	}

	_setup_rR_dst(core, rRD, ARM_IR_RD);

	if(CCx.e)
		_alubox_dpi_fn[DPI_sOPERATION](core, &GPR(rR(D)));
	else
		_alubox_dpi_no_wb_fn[DPI_OPERATION](core, &GPR(rR(D)));

	_arm_inst_dpi_final(core);
}

static void _arm_inst_ldst(soc_core_p core)
{
	_arm_ldst_ea(core);

	if(BTST(IR, 26))
		_arm_ldst(core);
	else
		_arm_ldst_sh(core);

	soc_core_trace_inst_ldst(core);
}

static void _arm_inst_ldstm(soc_core_p core,
	uint8_t user_mode_regs)
{
	if(LDST_BIT(l20))
	{
		vR(D) = soc_core_read(core, vR(EA), sizeof(uint32_t));

		if(0) LOG("r(%u)==[0x%08x](0x%08x)", rR(D), vR(EA), vR(D));

		if(user_mode_regs)
			soc_core_reg_usr(core, rR(D), &vR(D));
		else
			soc_core_reg_set(core, rR(D), vR(D));
	}
	else
	{
		if(user_mode_regs)
			vR(D) = soc_core_reg_usr(core, rR(D), 0);
		else
			vR(D) = soc_core_reg_get(core, rR(D));

		if(0) LOG("[0x%08x]==r(%u)(0x%08x)", vR(EA), rR(D), vR(D));

		soc_core_write(core, vR(EA), sizeof(uint32_t), vR(D));
	}

	vR(EA) += sizeof(uint32_t);
}

static void _arm_inst_b_bl_blx(soc_core_p core, int link, int blx_hl)
{
	if(_check_pedantic_arm_decode_fault) {
		if(ARM_INST_B != (IR & ARM_INST_B_MASK))
			DECODE_FAULT;
	}

	const int blx = (0 != blx_hl);
	const int32_t offset = mlBFMOVs(IR, 23, 0, 2) | blx_hl;
	const uint32_t new_pc = (ARM_PC + offset);
	const int thumb = new_pc & 1;

	const int splat = _trace_bx_0 && !blx && (new_pc == ARM_IP_NEXT);
	CORE_TRACE("b%s%s(0x%08x) /* %c(%s0x%08x) hl = %01u */",
		link ? "l" : "", blx ? "x" : "", new_pc & ~1, thumb ? 'T' : 'A', splat ? "x" : "", offset, blx_hl);

	if(link)
		CORE_TRACE_LINK(PC);

	CORE_TRACE_BRANCH(new_pc);

	if(likely(CCx.e))
	{
		if(link)
			LR = ARM_IP_NEXT;

		PC = new_pc;
	}
}

static void arm_inst_b_bl(soc_core_p core)
{
	const int link = BEXT(IR, ARM_INST_BIT_LINK);

	_arm_inst_b_bl_blx(core, link, 0);
}

static void arm_inst_blx(soc_core_p core)
{
	const int hl = BMOV(IR, ARM_INST_BIT_LINK, 1) | 1;

	CORE_T(CCx.s = "AL");
	CCx.e = 1;

	_arm_inst_b_bl_blx(core, 1, hl);
	soc_core_reg_set_thumb(core, 1);
}

static void arm_inst_bx(soc_core_p core)
{
	_setup_rR_vR_src(core, rRM, ARM_IR_RM);

	const int link = BEXT(IR, 5);

	const uint32_t new_pc = vR(M);
	const int thumb = new_pc & 1;

	CORE_TRACE("b%sx(%s) /* %c(0x%08x) */",
		link ? "l" : "", rR_NAME(M), thumb ? 'T' : 'A', new_pc & ~1);

	if(link)
		CORE_TRACE_LINK(PC);

	CORE_TRACE_BRANCH(new_pc);

	if(likely(CCx.e))
	{
		if(link)
			LR = ARM_IP_NEXT;

		soc_core_reg_set_pcx(core, new_pc);
	}
}

static void arm_inst_dp_immediate(soc_core_p core)
{
	_setup_rR_vR(M, ~0, mlBFEXT(IR, 7, 0));
	_setup_rR_vR(S, ~0, mlBFMOV(IR, 11, 8, 1));

	rR(SOP) = __alubox_shift_ror;

	_arm_inst_dp(core);
}

static void arm_inst_dp_immediate_shift(soc_core_p core)
{
	_setup_rR_vR_src(core, rRM, ARM_IR_RM);
	_setup_rR_vR(S, ~0, mlBFEXT(IR, 11, 7));

	rR(SOP) = DPI_SHIFT_OP;

	__alubox_arm_shift_sop_immediate_x(core);
	_arm_inst_dp(core);
}

static void arm_inst_dp_register_shift(soc_core_p core)
{
	assert(0 == DPI_BIT(x7));

	_setup_rR_vR_src(core, rRM, ARM_IR_RM);
	_setup_rR_vR_src(core, rRS, ARM_IR_RS);

	rR(SOP) = DPI_SHIFT_OP;

	vR(S) &= _BM(7);

	if(CCx.e)
		CYCLE++;

	_arm_inst_dp(core);
}

static void arm_inst_ldst_immediate_offset(soc_core_p core)
{
	_setup_rR_vR(M, ~0, mlBFEXT(IR, 11, 0));
	vR(SOP) = vR(M);

	return(_arm_inst_ldst(core));
}

static void arm_inst_ldst_immediate_offset_sh(soc_core_p core)
{
	_setup_rR_vR(M, ~0, mlBFMOV(IR, 11, 8, 4) | mlBFEXT(IR, 3, 0));
	vR(SOP) = vR(M);

	return(_arm_inst_ldst(core));
}

static void arm_inst_ldst_register_offset_sh(soc_core_p core)
{
	assert(0 == mlBFEXT(IR, 11, 8));
	
	_setup_rR_vR_src(core, rRM, ARM_IR_RM);
	vR(SOP) = vR(M);

	return(_arm_inst_ldst(core));
}

static void arm_inst_ldst_scaled_register_offset(soc_core_p core)
{
	_setup_rR_vR_src(core, rRM, ARM_IR_RM);
	_setup_rR_vR(S, ~0, mlBFEXT(IR, 11, 7));

	rR(SOP) = mlBFEXT(IR, 6, 5);

	__alubox_arm_shift_sop_immediate(core);

	return(_arm_inst_ldst(core));
}

static void arm_inst_ldstm(soc_core_p core)
{
	if(_check_pedantic_arm_decode_fault) {
		if(ARM_INST_LDSTM != (IR & ARM_INST_LDSTM_MASK))
			DECODE_FAULT;
	}

	const csx_p csx = core->csx;

	_setup_rR_vR(M, ~0, mlBFEXT(IR, 15, 0));
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);

	const unsigned rcount = (__builtin_popcount(vR(M)) << 2);

	const uint32_t sp_in = vR(N);
	uint32_t sp_out = sp_in;

	/*
	 * DA	!LDST_BIT(u23) && !LDST_BIT(p24)
	 * DB	!LDST_BIT(u23) && LDST_BIT(p24)
	 * IA	LDST_BIT(u23) && !LDST_BIT(p24)
	 * IB	LDST_BIT(u23) && LDST_BIT(p24)
	 *
	 */

	uint32_t start_address = 0;
	uint32_t end_address = 0;

	if(LDST_BIT(u23)) /* increment */
	{
		start_address = sp_in + (LDST_BIT(p24) << 2);
		end_address = start_address + rcount;
		sp_out += rcount;
	}
	else /* decrement */
	{
		end_address = sp_in + ((0 == LDST_BIT(p24)) << 2);
		start_address = end_address - rcount;
		sp_out -= rcount;
	}

	if(0) LOG("sp_in = 0x%08x, start_address = 0x%08x, end_address = 0x%08x",
		sp_in, start_address, end_address);
	if(0) LOG("sp_out = 0x%08x", sp_out);

	const char *opstr; (void)opstr;
	if(0 && rSP == rR(N))
		opstr = LDST_BIT(l20) ? "pop" : "push";
	else
		opstr = LDST_BIT(l20) ? "ldm" : "stm";

	char reglist[17]; (void)reglist;
	for(int i = 0; i <= 15; i++)
	{
		uint8_t c = (i > 9 ? ('a' + (i - 10)) : '0' + i);
		reglist[i] = BTST(vR(M), i) ? c : '.';
	}
	reglist[16] = 0;

	const int load_spsr = LDST_BIT(s22) && LDST_BIT(l20) && BTST(vR(M), 15);

	const int user_mode_regs_load = LDST_BIT(s22) && LDST_BIT(l20) && !LDST_BIT(w21) && !BTST(vR(M), 15);
	const int user_mode_regs_store = LDST_BIT(s22) && !LDST_BIT(l20);

	if(0) LOG("s = %01u, umrl = %01u, umrs = %01u", LDST_BIT(s22), user_mode_regs_load, user_mode_regs_store);

	const int user_mode_regs = user_mode_regs_load || user_mode_regs_store;

	CORE_TRACE("%s%c%c(%s%s, {%s}%s%s) /* 0x%08x */" ,
		opstr, LDST_BIT(u23) ? 'i' : 'd', LDST_BIT(p24) ? 'b' : 'a',
		rR_NAME(N), LDST_BIT(w21) ? "!" : "", reglist,
		user_mode_regs ? ", USER" : "",
		load_spsr ? ", SPSR" : "", sp_in);

	vR(EA) = start_address;

	if(CCx.e)
	{
		if(CP15_reg1_bit(u)) {
			if(vR(EA) & 3)
				soc_core_exception(core, _EXCEPTION_DataAbort);
		}
		else
			vR(EA) &= ~3;

		for(rR(D) = 0; rR(D) < 15; rR(D)++)
		{
			if(BTST(vR(M), rR(D)))
			{
				CYCLE++;
				_arm_inst_ldstm(core, user_mode_regs);
			}
		}

		if(BTST(vR(M), 15)) {
			if(LDST_BIT(l20))
			{
				vR(D) = soc_core_read(core, vR(EA), sizeof(uint32_t));
				if(0) LOG("r(%u)==[0x%08x](0x%08x)", 15, vR(EA), vR(D));
				if(_arm_version >= arm_v5t)
					soc_core_reg_set_pcx(core, vR(D));
				else
					PC = vR(D) & ~3;
			}
			else
			{
				vR(D) = ARM_PC;
				if(0) LOG("[0x%08x]==r(%u)(0x%08x)", vR(EA), 15, vR(D));
				soc_core_write(core, vR(EA), sizeof(uint32_t), vR(D));
			}
		}

		if(load_spsr && core->spsr) {
			LOG_ACTION(soc_core_psr_mode_switch(core, *core->spsr));
			soc_core_reg_set_thumb(core, CPSR & CPSR_C(Thumb));
		}

		if((LDST_BIT(w21) && (user_mode_regs || load_spsr))
			|| (user_mode_regs && load_spsr))
				LOG_ACTION(exit(1));

		if(LDST_BIT(w21))
		{
			if(0) LOG("ea = 0x%08x", vR(EA));

//			assert(end_address == vR(EA));
			if(end_address == vR(EA))
				soc_core_reg_set(core, rR(N), sp_out);
			else
				UNDEFINED;
		}
	}
}

static void arm_inst_mcr_mrc(soc_core_p core)
{
	if(_check_pedantic_arm_decode_fault) {
		if(ARM_INST_MCR_MRC != (IR & ARM_INST_MCR_MRC_MASK))
			DECODE_FAULT;
	}

	soc_core_arm_decode_coproc(core);

	CORE_TRACE("m%s(p(%u), %u, %s, %s, %s, %u)",
		MCRC_L ? "rc" : "cr", MCRC_CPx, MCRC_OP1,
		rR_NAME(D),
		creg_name[rR(N)], creg_name[rR(M)],
		MCRC_OP2);

	if(CCx.e)
	{
		uint32_t *write = MCRC_L ? 0 : &vR(D);
		const uint32_t result = csx_coprocessor_access(core->csx->cp, write);
		if(MCRC_L && (rPC == rR(D))) {
			CPSR &= ~SOC_CORE_PSR_NZCV;
			CPSR |= result & SOC_CORE_PSR_NZCV;
		} else
			vR(D) = result;
	}
}

static void arm_inst_mla(soc_core_p core)
{
	_setup_rR_vR_src(core, rRM, ARM_IR_RM);
	_setup_rR_vR_src(core, rRN, ARM_IR_RN);
	_setup_rR_vR_src(core, rRS, ARM_IR_RS);

	_setup_rR_dst(core, rRD, ARM_IR_RD);

	vR(D) = (vR(M) * vR(S)) + vR(N);

	CORE_TRACE_START();
	_CORE_TRACE_("mla%s(", DPI_BIT(s20) ? "s" : "");
	_CORE_TRACE_("%s", rR_NAME(D));
	_CORE_TRACE_(", %s", rR_NAME(M));
	_CORE_TRACE_(", %s", rR_NAME(S));
	_CORE_TRACE_(", %s", rR_NAME(N));

	_CORE_TRACE_("); /* (0x%08x * 0x%08x) + 0x%08x = 0x%08x */",
		vR(M), vR(S), vR(N), vR(D));

	CORE_TRACE_END();

	if(CCx.e) {
		soc_core_reg_set(core, rR(D), vR(D));
		if(DPI_BIT(s20))
			soc_core_flags_nz(core, vR(D));
	}
}

static void arm_inst_mrs(soc_core_p core)
{
	uint32_t test = 0, result = 0;

	const int tsbo = _check_sbo(IR, 19, 16, &test, &result);
	if(tsbo)
		LOG("!! sbo(opcode = 0x%08x, 19, 16, =0x%08x, =0x%08x (%u))", IR, test, result, tsbo);

	const int tsbz = _check_sbz(IR, 11, 0, &test, &result);
	if(tsbz)
		LOG("!! sbz(opcode = 0x%08x, 11, 0, =0x%08x, =0x%08x (%u))", IR, test, result, tsbz);

	if(tsbo || tsbz)
		UNPREDICTABLE;

	_setup_rR_dst(core, rRD, ARM_IR_RD);

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

	CORE_TRACE("mrs(%s, %s) /* 0x%08x */", rR_NAME(D), psrs, vR(D));

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
	csx_p csx = core->csx; (void)csx;

	uint32_t test = 0, result = 0;

	const int tsbo = _check_sbo(IR, 15, 12, &test, &result);
	if(tsbo) {
		LOG("!! sbo(opcode = 0x%08x, 15, 12, =0x%08x, =0x%08x (%u))", IR, test, result, tsbo);
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
				LOG("!! sbz(opcode = 0x%08x, 11, 8, =0x%08x, =0x%08x (%u))", IR, test, result, tsbz);
				UNPREDICTABLE;
			}

			_setup_rR_vR_src(core, rRM, ARM_IR_RM);
			operand = vR(M);
		}
		else
		{
			UNIMPLIMENTED;
		}
	}

	const uint32_t unalloc_mask = soc_core_msr_unalloc_mask[arm_v5tej];
	if(0) LOG("unalloc_mask = 0x%08x", unalloc_mask);

	if(operand & unalloc_mask)
	{
		UNPREDICTABLE;
	}

	const uint32_t byte_mask =
		(BTST(field_mask, 0) ? (0xff << 0) : 0)
		| (BTST(field_mask, 1) ? (0xff << 8) : 0)
		| (BTST(field_mask, 2) ? (0xff << 16) : 0)
		| (BTST(field_mask, 3) ? (0xff << 24) : 0);

	const uint32_t state_mask = soc_core_msr_state_mask[arm_v5tej];
	const uint32_t user_mask = soc_core_msr_user_mask[arm_v5tej];
	const uint32_t priv_mask = soc_core_msr_priv_mask[arm_v5tej];

	if(0) LOG("state_mask = 0x%08x, user_mask = 0x%08x, priv_mask = 0x%08x",
		state_mask, user_mask, priv_mask);

	if(0) LOG("field_mask = 0x%08x, byte_mask = 0x%08x", field_mask, byte_mask);

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

		if(0) LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x", SP, LR, IP);

		if(BTST(saved_psr, SOC_CORE_PSR_BIT_T) != BTST(new_psr, SOC_CORE_PSR_BIT_T))
			CORE_TRACE_THUMB;

		if(CCx.e)
			soc_core_psr_mode_switch(core, new_psr);
	}

	uint8_t cpsrs[5];
	cpsrs[0] = BTST(field_mask, 3) ? 'F' : 'f';
	cpsrs[1] = BTST(field_mask, 2) ? 'S' : 's';
	cpsrs[2] = BTST(field_mask, 1) ? 'X' : 'x';
	cpsrs[3] = BTST(field_mask, 0) ? 'C' : 'c';
	cpsrs[4] = 0;

	const uint8_t cs = bit_r ? 'S' : 'C';

//	soc_core_trace_psr(core, 0, saved_psr);

	const uint32_t operand_masked = operand & mask;

	if(bit_i)
	{
		CORE_TRACE("msr(%cPSR_%s, 0x%08x) /* 0x%08x & 0x%08x -> 0x%08x, 0x%08x */",
			cs, cpsrs, operand, operand, mask, operand_masked, new_psr);
	}
	else
	{
		CORE_TRACE("msr(%cPSR_%s, %s) /* 0x%08x & 0x%08x -> 0x%08x, 0x%08x */",
			cs, cpsrs, rR_NAME(M), operand, mask, operand_masked, new_psr);
	}

	if(0) LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x", SP, LR, IP);

//	soc_core_trace_psr(core, 0, new_psr);
}

static void arm_inst_smull(soc_core_p core)
{
	_setup_rR_vR_src(core, rRS, ARM_IR_RS);
	_setup_rR_vR_src(core, rRM, ARM_IR_RM);

	_setup_rR_dst(core, rRD, ARM_IR_RD);
	_setup_rR_dst(core, rRN, ARM_IR_RN);

	const int64_t result = (int32_t)vR(M) * (int32_t)vR(S);

	vR(D) = result & 0xffffffff;
	vR(N) = (result >> 32) & 0xffffffff;

	CORE_TRACE_START();
	_CORE_TRACE_("smull%s(", DPI_BIT(s20) ? "s" : "");
	_CORE_TRACE_("%s", rR_NAME(D));
	_CORE_TRACE_(":%s", rR_NAME(N));
	_CORE_TRACE_(", %s", rR_NAME(M));
	_CORE_TRACE_(", %s", rR_NAME(S));

	_CORE_TRACE_("); /* 0x%08x * 0x%08x = 0x%016llx */",
		vR(M), vR(S), result);

	CORE_TRACE_END();

	if(CCx.e) {
		soc_core_reg_set(core, rR(D), vR(D));
		soc_core_reg_set(core, rR(D), vR(D));
		if(DPI_BIT(s20)) {
			BMAS(CPSR, SOC_CORE_PSR_BIT_N, BEXT(vR(D), 31));
			BMAS(CPSR, SOC_CORE_PSR_BIT_Z, (0 == result));
		}
	}
}

static void arm_inst_umull(soc_core_p core)
{
	_setup_rR_vR_src(core, rRS, ARM_IR_RS);
	_setup_rR_vR_src(core, rRM, ARM_IR_RM);

	_setup_rR_dst(core, rRD, ARM_IR_RD);
	_setup_rR_dst(core, rRN, ARM_IR_RN);

	const uint64_t result = (uint32_t)vR(M) * (uint32_t)vR(S);

	vR(D) = result & 0xffffffff;
	vR(N) = (result >> 32) & 0xffffffff;

	CORE_TRACE_START();
	_CORE_TRACE_("umull%s(", DPI_BIT(s20) ? "s" : "");
	_CORE_TRACE_("%s", rR_NAME(D));
	_CORE_TRACE_(":%s", rR_NAME(N));
	_CORE_TRACE_(", %s", rR_NAME(M));
	_CORE_TRACE_(", %s", rR_NAME(S));

	_CORE_TRACE_("); /* 0x%08x * 0x%08x = 0x%016llx */",
		vR(M), vR(S), result);

	CORE_TRACE_END();

	if(CCx.e) {
		soc_core_reg_set(core, rR(D), vR(D));
		soc_core_reg_set(core, rR(D), vR(D));
		if(DPI_BIT(s20)) {
			BMAS(CPSR, SOC_CORE_PSR_BIT_N, BEXT(vR(D), 31));
			BMAS(CPSR, SOC_CORE_PSR_BIT_Z, (0 == result));
		}
	}
}

/* **** */

static uint8_t soc_core_arm_check_cc(soc_core_p core)
{
	return(soc_core_check_cc(core, ARM_IR_CC));
}

static void soc_core_arm_step_group0_ldst(soc_core_p core)
{
	if(LDST_FLAG_SH) {
		if(LDST_FLAG_SH_I)
			return(arm_inst_ldst_immediate_offset_sh(core));
		else
			return(arm_inst_ldst_register_offset_sh(core));
	} else {
		switch(mlBFTST(IR, 27, 21)) {
			case 0x00200000:
				return(arm_inst_mla(core));
			case 0x00800000:
				return(arm_inst_umull(core));
			case 0x00c00000:
				return(arm_inst_smull(core));
		}
	}

	UNIMPLIMENTED;
}

static void soc_core_arm_step_group0_misc(soc_core_p core)
{
	if(ARM_INST_BX == (IR & ARM_INST_BX_MASK))
		return(arm_inst_bx(core));
	if(ARM_INST_MRS == (IR & ARM_INST_MRS_MASK))
		return(arm_inst_mrs(core));
	if((ARM_INST_MSR_I == (IR & ARM_INST_MSR_I_MASK))
		|| (ARM_INST_MSR_R == (IR & ARM_INST_MSR_R_MASK)))
			return(arm_inst_msr(core));

	UNIMPLIMENTED;
}

static void soc_core_arm_step_group0(soc_core_p core)
{
	if(BTST(IR, 4)) {
		if(BTST(IR, 7))
			return(soc_core_arm_step_group0_ldst(core));
		else {
			if((2 == mlBFEXT(IR, 24, 23)) && !BTST(IR, 20))
				return(soc_core_arm_step_group0_misc(core));
			else
				return(arm_inst_dp_register_shift(core));
		}
	} else {
		if((2 == mlBFEXT(IR, 24, 23)) && !BTST(IR, 20))
			return(soc_core_arm_step_group0_misc(core));
		else
			return(arm_inst_dp_immediate_shift(core));
	}

	UNIMPLIMENTED;
}

static void soc_core_arm_step_group1(soc_core_p core)
{
	if(2 == mlBFEXT(IR, 24, 23)) {
		if(0 == mlBFEXT(IR, 21, 20)) {
			UNDEFINED;
		} else if(2 == mlBFEXT(IR, 21, 20))
			UNIMPLIMENTED; /* move immediate to status register */
	}

	return(arm_inst_dp_immediate(core));
}

static void soc_core_arm_step_group7(soc_core_p core)
{
	if(ARM_INST_MCR_MRC == (IR & ARM_INST_MCR_MRC_MASK))
		return(arm_inst_mcr_mrc(core));

	UNIMPLIMENTED;
}

void soc_core_arm_step(soc_core_p core)
{
	IR = soc_core_reg_pc_fetch_step_arm(core);

	const unsigned opcode = mlBFEXT(IR, 27, 25);

	CCx.e = soc_core_arm_check_cc(core);

	if(INST_CC_NV != ARM_IR_CC) {
		switch(opcode)
		{
			case 0x00: /* xxxx 000x xxxx xxxx */
				return(soc_core_arm_step_group0(core));
				break;
			case 0x01: /* xxxx 001x xxxx xxxx */
				return(soc_core_arm_step_group1(core));
				break;
			case 0x02: /* xxxx 010x xxxx xxxx */
				return(arm_inst_ldst_immediate_offset(core));
				break;
			case 0x03:
				if(!BTST(IR, 4))
					return(arm_inst_ldst_scaled_register_offset(core));
				else
					goto decode_fault;
				break;
			case 0x04: /* xxxx 100x xxxx xxxx */
				return(arm_inst_ldstm(core));
				break;
			case 0x05: /* xxxx 101x xxxx xxxx */
				return(arm_inst_b_bl(core));
				break;
			case 0x07: /* xxxx 111x xxxx xxxx */
				return(soc_core_arm_step_group7(core));
				break;
			default:
				goto decode_fault;
		}
	} else if(INST_CC_NV == ARM_IR_CC) {
		switch(opcode) {
			case 0x05: /* xxxx 101x xxxx xxxx */
				return(arm_inst_blx(core));
				break;
			default:
				goto decode_fault;
		}
	}

decode_fault:
	LOG("IR[27:25] = %1u", opcode);

	DECODE_FAULT;
}

void soc_core_arm_step_profile(soc_core_p core)
{
	const uint64_t dtime = _profile_soc_core_step_arm ? get_dtime() : 0;

	soc_core_arm_step(core);

	CSX_PROFILE_STAT_COUNT(soc_core.step.arm, dtime);
}

