#include "soc_core_arm.h"
#include "soc_core_arm_decode.h"
#include "soc_core_arm_inst.h"

#include "soc_core_cp15.h"
#include "soc_core_disasm.h"
#include "soc_core_psr.h"
#include "soc_core_shifter.h"
#include "soc_core_strings.h"
#include "soc_core_trace.h"
#include "soc_core_trace_arm.h"
#include "soc_core_utility.h"

/* **** */

#include "bitfield.h"
#include "log.h"
#include "shift_roll.h"

/* **** */

#include "alu_box.h"

typedef uint32_t (*alubox_fn)(soc_core_p core, uint32_t rn, uint32_t rm);

alubox_fn _alubox_arm_dpi_fn[2][16] = {{
		_alubox_and,	_alubox_eor,	_alubox_sub,	_alubox_rsb,
		_alubox_add,	_alubox_adc,	_alubox_sbc,	_alubox_rsc,
		0,				0,				0,				0,
		_alubox_orr,	_alubox_mov,	_alubox_bic,	_alubox_mvn,
	}, {
		_alubox_ands,	_alubox_eors,	_alubox_subs,	_alubox_rsbs,
		_alubox_adds,	_alubox_adcs,	_alubox_sbcs,	_alubox_rscs,
		_alubox_tsts,	_alubox_teqs,	_alubox_cmps,	_alubox_cmns,
		_alubox_orrs,	_alubox_movs,	_alubox_bics,	_alubox_mvns,
}};

/* **** */

static void _arm_inst_dpi_final(soc_core_p core)
{
	soc_core_trace_inst_dpi(core);

	if(rPC == rR(D))
	{
		const int thumb = DPI_BIT(s20) && core->spsr
			&& BTST(*core->spsr, SOC_CORE_PSR_BIT_T);

		if(thumb)
			CORE_TRACE_THUMB;

		CORE_TRACE_BRANCH(vR(D));
	}

	if(CCx.e)
	{
		if((rR(S) & 0x0f) == rR(S))
			CYCLE++;

		if(DPI_WB)
		{
			if(rPC == rR(D))
				soc_core_reg_set_pcx(core, vR(D));
			else
				soc_core_reg_set(core, rR(D), vR(D));
		}

		if(DPI_BIT(s20) && (rPC == rR(D)))
		{
			if(core->spsr)
				soc_core_psr_mode_switch(core, *core->spsr);
			else
				UNPREDICTABLE;
		}
	}
}

static void _arm_inst_dp(soc_core_p core)
{
	const int get_rn = (ARM_DPI_OPERATION_MOV != DPI_OPERATION);

	soc_core_arm_decode_rn_rd(core, get_rn, 0);

	alubox_fn dpi_fn = _alubox_arm_dpi_fn[CCx.e && DPI_BIT(s20)][DPI_OPERATION];
	assert(0 != dpi_fn);
	
	vR(D) = dpi_fn(core, vR(N), vR(SOP_V));

	_arm_inst_dpi_final(core);
}

unsigned long int _arm_ror_c(unsigned long int v,
	unsigned long int shift,
	unsigned long int* carry)
{
	uint32_t result = _ror(v, shift);
	*carry = _lsr(v, 32 - shift);

	return(result);
}

typedef unsigned long int (*sop_fn_t)(unsigned long int v,
	unsigned long int shift,
	unsigned long int* carry);

static void _arm_inst_dp_shift_operand(soc_core_p core) {
	sop_fn_t sop_fn_list[4] = {
		_lsl_c, _lsr_c, (sop_fn_t)_asr_c, _arm_ror_c
		};

	if(vR(S)) {
		unsigned long int carry_out;
		vR(SOP_V) = sop_fn_list[DPI_SHIFT_OP](vR(M), vR(S), &carry_out);
		vR(SOP_C) = carry_out;
	} else {
		vR(SOP_V) = vR(M);
		vR(SOP_C) = BEXT(CPSR, SOC_CORE_PSR_BIT_C);
	}
}

static void _arm_inst_ldst(soc_core_p core,
	soc_core_ldst_p ls)
{
//	ls->ldstx = mlBFEXT(IR, 27, 25);
	soc_core_arm_decode_rd(core, !LDST_BIT(l20));
	soc_core_arm_decode_rn(core, 1);

	ls->ea = vR(N);

	if(LDST_BIT(p24))
	{
		if(LDST_BIT(u23))
			ls->ea += ls->index;
		else
			ls->ea -= ls->index;
	}

	if(LDST_BIT(l20))
	{
		vR(D) = soc_core_read(core, ls->ea, ls->rw_size);

		/*	ARMv5, CP15_r1_Ubit == 0 */
		if(ls->rw_size == sizeof(uint32_t))
			vR(D) = _ror(vR(D), ((ls->ea & 3) << 3));

		if(LDST_FLAG_S) /* sign extend ? */
			vR(D) = mlBFEXTs(vR(D), (ls->rw_size << 3), 0);
	}

	soc_core_trace_inst_ldst(core, ls);

	/*	ARMv5, CP15_r1_Ubit == 0 */
	if(LDST_BIT(l20) && (ls->rw_size == sizeof(uint32_t)))
		assert(0 == (ls->ea & 3));

	if(LDST_BIT(l20) && (rPC == rR(D)))
		CORE_TRACE_BRANCH(vR(D));

	if(CCx.e)
	{
		if(!LDST_BIT(p24))
		{
			if(LDST_BIT(u23))
				ls->ea += ls->index;
			else
				ls->ea -= ls->index;
		}

		if(!LDST_BIT(p24) || LDST_BIT(w21)) /* base update? */
			soc_core_reg_set(core, rR(N), ls->ea);

		if(LDST_BIT(l20))
		{
			if(rPC == rR(D))
				soc_core_reg_set_pcx(core, vR(D));
			else
				soc_core_reg_set(core, rR(D), vR(D));
		}
		else
		{
			if(ls->rw_size == sizeof(uint32_t))
				ls->ea &= ~3;

			soc_core_write(core, ls->ea, vR(D), ls->rw_size);
		}
	}
}

static void _arm_inst_ldst_iro_sro(soc_core_p core,
	soc_core_ldst_p ls)
{
	ls->rw_size = LDST_BIT(b22) ? sizeof(uint8_t) : sizeof(uint32_t);

	return(_arm_inst_ldst(core, ls));
}

static void _arm_inst_ldst_sh(soc_core_p core,
	soc_core_ldst_p ls)
{
	switch(BMOV(IR, LDST_BIT_l20, 2) | mlBFEXT(IR, 6, 5)) {
		case 0x01:
		case 0x05:
			ls->rw_size = sizeof(uint16_t);
			break;
		case 0x02:
		case 0x03:
			ls->rw_size = sizeof(uint64_t);
			break;
		case 0x06:
			ls->rw_size = sizeof(int8_t);
			break;
		case 0x07:
			ls->rw_size = sizeof(int16_t);
			break;
		default:
			soc_core_disasm_arm(core, PC, IR);
			LOG_ACTION(exit(-1));
			break;
	}

	ls->index = vR(M);

	return(_arm_inst_ldst(core, ls));
}

static void _arm_inst_ldstm(soc_core_p core,
	soc_core_ldst_p ls,
	soc_core_reg_t i,
	uint8_t user_mode_regs)
{
	uint32_t rxx_v = 0;

	/* CP15_r1_Ubit == 0 */
	const uint32_t ea = ls->ea & ~3;

	if(LDST_BIT(l20))
	{
		rxx_v = soc_core_read(core, ea, sizeof(uint32_t));

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

		soc_core_write(core, ea, rxx_v, sizeof(uint32_t));
	}

	ls->ea += sizeof(uint32_t);
}

static void arm_inst_b(soc_core_p core)
{
	const int blx = (0x0f == mlBFEXT(IR, 31, 28));
	const int hl = BEXT(IR, ARM_INST_BIT_LINK);
	const int32_t offset = mlBFEXTs(IR, 23, 0);

	const int link = blx || (!blx && hl);
	uint32_t new_pc = PC_ARM + (offset << 2);

	if(blx)
	{
		new_pc |= (hl << 1) | 1;
		CORE_T(CCx.s = "AL");
		CCx.e = 1;
	}

	CORE_TRACE("b%s%s(0x%08x) /* %c(0x%08x) hl = %01u */",
		link ? "l" : "", blx ? "x" : "", new_pc & ~1, new_pc & 1 ? 'T' : 'A', offset, hl);

	if(link)
		CORE_TRACE_LINK(PC);

	CORE_TRACE_BRANCH(new_pc);

	if(CCx.e)
	{
		if(link)
			LR = PC;

		soc_core_reg_set_pcx(core, new_pc);
	}
}

static void arm_inst_bx(soc_core_p core)
{
	soc_core_arm_decode_rm(core, 1);

	const int link = BEXT(IR, 5);

	const uint32_t new_pc = vR(M);
	const int thumb = new_pc & 1;

	CORE_TRACE("b%sx(%s) /* %c(0x%08x) */",
		link ? "l" : "", rR_NAME(M), thumb ? 'T' : 'A', new_pc & ~1);

	if(link)
		CORE_TRACE_LINK(PC);

	CORE_TRACE_BRANCH(new_pc);

	if(CCx.e)
	{
		if(link)
			LR = PC;

		soc_core_reg_set_pcx(core, new_pc);
	}
}

/*
static void arm_inst_dpi(soc_core_p core)
{
	soc_core_arm_decode_shifter_operand(core);

	const int get_rn = (ARM_DPI_OPERATION_MOV != DPI_OPERATION);

	soc_core_arm_decode_rn_rd(core, get_rn, 0);

	alubox_fn dpi_fn = _alubox_arm_dpi_fn[CCx.e && DPI_BIT(s20)][DPI_OPERATION];
	assert(0 != dpi_fn);
	
	vR(D) = dpi_fn(core, vR(N), vR(SOP_V));

	_arm_inst_dpi_final(core);
	return;

exit_fault:
	LOG("operation = 0x%02x", DPI_OPERATION);
	soc_core_disasm_arm(core, IP, IR);
	UNIMPLIMENTED;
}
*/

static void arm_inst_dp_immediate(soc_core_p core)
{
	_setup_rR_vR(M, ~0, mlBFEXT(IR, 7, 0));
	_setup_rR_vR(S, ~0, mlBFMOV(IR, 11, 8, 1));

	vR(SOP_V) = _ror(vR(M), vR(S));

	if(vR(S))
		vR(SOP_C) = BEXT(vR(SOP_V), 31);
	else
		vR(SOP_C) = BEXT(CPSR, SOC_CORE_PSR_BIT_C);

//	_arm_inst_dp_shift_operand(core);
	_arm_inst_dp(core);
}

static void arm_inst_dp_immediate_shift(soc_core_p core)
{
	soc_core_arm_decode_rm(core, 1);

	_setup_rR_vR(S, ~0, mlBFEXT(IR, 11, 7));
	
	switch(DPI_SHIFT_OP) {
		case	SOC_CORE_SHIFTER_OP_ASR:
		case	SOC_CORE_SHIFTER_OP_LSR:
			if(!vR(S))
				vR(S) = 32;
			break;
	}

	_arm_inst_dp_shift_operand(core);
	_arm_inst_dp(core);
}

static void arm_inst_dp_register_shift(soc_core_p core)
{
	assert(0 == DPI_BIT(x7));
	
	soc_core_arm_decode_rm(core, 1);

	soc_core_decode_get(core, rRS, 11, 8, 1);
	vR(S) &= _BM(7);

	_arm_inst_dp_shift_operand(core);
	_arm_inst_dp(core);
}

static void arm_inst_ldst_immediate_offset(soc_core_p core)
{
	soc_core_ldst_t ls;

	_setup_rR_vR(M, ~0, mlBFEXT(IR, 11, 0));
	ls.index = vR(M);

	return(_arm_inst_ldst_iro_sro(core, &ls));
}

static void arm_inst_ldst_immediate_offset_sh(soc_core_p core)
{
	soc_core_ldst_t ls;

	_setup_rR_vR(M, ~0, mlBFMOV(IR, 11, 8, 4) | mlBFEXT(IR, 3, 0));

	return(_arm_inst_ldst_sh(core, &ls));
}

static void arm_inst_ldst_register_offset_sh(soc_core_p core)
{
	soc_core_ldst_t ls;

	soc_core_arm_decode_rm(core, 1);

	return(_arm_inst_ldst_sh(core, &ls));
}

static void arm_inst_ldst_scaled_register_offset(soc_core_p core)
{
	soc_core_ldst_t ls; /* TODO: not tested/verified! */

	_setup_rR_vR(S, ~mlBFEXT(IR, 6, 5), mlBFEXT(IR, 11, 7));

	soc_core_arm_decode_rm(core, 1);

	uint32_t index = 0;

	switch((int8_t)rR(S)) {
		case ~0: /* lsl */
			index = _lsl(vR(M), vR(S));
			break;
		case ~1: /* lsr */
			if(vR(S))
				index = _lsr(vR(M), vR(S));
			else
				index = 0;
			break;
		case ~2: /* asr */
			if(vR(S))
				index = _asr(vR(M), vR(S));
			else
				index = -1;
			break;
		case ~3: /* ror/rrx */
			if(vR(S))
				index = _ror(vR(M), vR(S));
			else {
				index = BMOV(CPSR, SOC_CORE_PSR_BIT_C, 31);
				index |= _lsr(vR(M), 1);
			}
		default:
			soc_core_disasm_arm(core, PC, IR);
			LOG_ACTION(exit(-1));
			break;
	}

	ls.index = index;

	return(_arm_inst_ldst_iro_sro(core, &ls));
}

static void arm_inst_ldstm(soc_core_p core)
{
	const csx_p csx = core->csx;

	soc_core_ldst_t ls;
	ls.rw_size = sizeof(uint32_t);

	_setup_rR_vR(M, ~0, mlBFEXT(IR, 15, 0));
	soc_core_arm_decode_rn(core, 1);

	const uint8_t rcount = (__builtin_popcount(vR(M)) << 2);

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
		end_address = sp_in + (!LDST_BIT(p24) << 2);
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

	ls.ea = start_address;

	if(CCx.e)
	{
		if(CP15_reg1_Ubit) {
			if(ls.ea & 3)
				DataAbort();
		}
		else
			ls.ea &= ~3;

		for(int i = 0; i < 15; i++)
		{
			if(BTST(vR(M), i))
			{
				CYCLE++;
				_arm_inst_ldstm(core, &ls, i, user_mode_regs);
			}
		}

		if(BTST(vR(M), 15)) {
			const uint32_t ea = ls.ea;

			uint32_t rxx_v = 0;

			if(LDST_BIT(l20))
			{
				rxx_v = soc_core_read(core, ea, sizeof(uint32_t));
				if(0) LOG("r(%u)==[0x%08x](0x%08x)", 15, ea, rxx_v);
				if(_arm_version >= arm_v5t)
					soc_core_reg_set_pcx(core, rxx_v);
				else
					PC = rxx_v & ~3;
			}
			else
			{
				rxx_v = PC_ARM;
				if(0) LOG("[0x%08x]==r(%u)(0x%08x)", ea, 15, rxx_v);
				soc_core_write(core, ea, rxx_v, sizeof(uint32_t));
			}
		}

		if(load_spsr && core->spsr)
			soc_core_psr_mode_switch(core, *core->spsr);

		if((LDST_BIT(w21) && (user_mode_regs || load_spsr))
			|| (user_mode_regs && load_spsr))
				LOG_ACTION(exit(1));

		if(LDST_BIT(w21))
		{
			if(0) LOG("ea = 0x%08x", ls.ea);

			assert(end_address == ls.ea);
			soc_core_reg_set(core, rR(N), sp_out);
		}
	}
}

static void arm_inst_mcr_mrc(soc_core_p core)
{
	soc_core_arm_decode_coproc(core);

	CORE_TRACE("m%s(p(%u), %u, %s, %s, %s, %u)",
		MCRC_L ? "rc" : "cr", MCRC_CPx, MCRC_OP1,
		rR_NAME(D),
		creg_name[rR(N)], creg_name[rR(M)],
		MCRC_OP2);

	if(CCx.e)
	{
		if(MCRC_L) {
			uint32_t rval = soc_core_cp15_read(core);
			if(rPC == rR(D)) {
				CPSR &= ~SOC_CORE_PSR_NZCV;
				CPSR |= rval & SOC_CORE_PSR_NZCV;
			} else
				vR(D) = rval;
		} else
			soc_core_cp15_write(core);
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

	soc_core_arm_decode_rd(core, 0);

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

			soc_core_arm_decode_rm(core, 1);
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

	soc_core_trace_psr(core, 0, saved_psr);

	if(bit_i)
	{
		CORE_TRACE("msr(%cPSR_%s, 0x%08x) /* 0x%08x & 0x%08x -> 0x%08x */",
			cs, cpsrs, operand, operand, mask, operand & mask);
	}
	else
	{
		CORE_TRACE("msr(%cPSR_%s, %s) /* 0x%08x & 0x%08x -> 0x%08x*/",
			cs, cpsrs, rR_NAME(M), operand, mask, operand & mask);
	}

	if(0) LOG("sp = 0x%08x, lr = 0x%08x, pc = 0x%08x", SP, LR, IP);

	soc_core_trace_psr(core, 0, new_psr);
}

/* **** */

#define ARM_IR_CC					mlBFEXT(IR, 31, 28)

static uint8_t soc_core_arm_check_cc(soc_core_p core)
{
	const uint8_t cc = ARM_IR_CC;
	return(soc_core_check_cc(core, cc));
}

const uint _inst0_0_i74 = _BV(7) | _BV(4);

const uint _inst0_1_misc = _BV(24);
const uint _inst0_1_misc_mask = mlBF(27, 23) | _BV(20);

const uint _inst1_0_undef = mlBF(25, 24);
const uint _inst1_0_mitsr = _inst1_0_undef | _BV(21);
const uint _inst1_0_mitsr_mask = mlBF(27, 23) | mlBF(21, 20);

const uint _inst3_i4_mask = _BV(4);

void soc_core_arm_step(soc_core_p core)
{
	IR = soc_core_reg_pc_fetch_step_arm(core);

	const uint opcode = mlBFEXT(IR, 27, 25);

	CCx.e = soc_core_arm_check_cc(core);

	if(INST_CC_NV != ARM_IR_CC) {
		switch(opcode)
		{
			case 0x00: /* xxxx 000x xxxx xxxx */
				if(_inst0_0_i74 == (IR & _inst0_0_i74)) {
					if(LDST_FLAG_SH_I)
						return(arm_inst_ldst_immediate_offset_sh(core));
					else
						return(arm_inst_ldst_register_offset_sh(core));
				} else if(_inst0_1_misc != (IR & _inst0_1_misc_mask)) {
					if(BEXT(IR, 4))
						return(arm_inst_dp_register_shift(core));
					else
						return(arm_inst_dp_immediate_shift(core));
//					if(ARM_INST_DP == (IR & ARM_INST_DP_MASK)) {
//						return(arm_inst_dpi(core));
//					}
				} else {
					if(ARM_INST_BX == (IR & ARM_INST_BX_MASK))
						return(arm_inst_bx(core));
					if(ARM_INST_MRS == (IR & ARM_INST_MRS_MASK))
						return(arm_inst_mrs(core));
					if((ARM_INST_MSR_I == (IR & ARM_INST_MSR_I_MASK))
						|| (ARM_INST_MSR_R == (IR & ARM_INST_MSR_R_MASK)))
							return(arm_inst_msr(core));
				}
				break;
			case 0x01: /* xxxx 001x xxxx xxxx */
				if(_inst1_0_mitsr == (IR & _inst1_0_mitsr_mask))
					;
				else if((_inst1_0_undef != (IR & _inst1_0_mitsr_mask))
					&&(ARM_INST_DP == (IR & ARM_INST_DP_MASK)))
						return(arm_inst_dp_immediate(core));
//						return(arm_inst_dpi(core));
				break;
			case 0x02: /* xxxx 010x xxxx xxxx */
				return(arm_inst_ldst_immediate_offset(core));
				break;
			case 0x03:
				if(!(IR & _inst3_i4_mask))
					return(arm_inst_ldst_scaled_register_offset(core));
				break;
			case 0x04: /* xxxx 100x xxxx xxxx */
				if(ARM_INST_LDSTM == (IR & ARM_INST_LDSTM_MASK))
					return(arm_inst_ldstm(core));
				break;
			case 0x05: /* xxxx 101x xxxx xxxx */
				if(ARM_INST_B == (IR & ARM_INST_B_MASK))
					return(arm_inst_b(core));
				break;
			case 0x07: /* xxxx 111x xxxx xxxx */
				if(ARM_INST_MCR_MRC == (IR & ARM_INST_MCR_MRC_MASK))
					return(arm_inst_mcr_mrc(core));
				break;
		}
	} else if(INST_CC_NV == ARM_IR_CC) {
		switch(opcode) {
			case 0x05: /* xxxx 101x xxxx xxxx */
				if(ARM_INST_B == (IR & ARM_INST_B_MASK))
					return(arm_inst_b(core));
				break;
		}
	}

decode_fault:
	switch(opcode)
	{
		case 0x00:
		case 0x01: {
			const uint dpi_opcode = mlBFEXT(IR, 24, 21);
			LOG(">> ir = 0x%08x, opcode = 0x%02x, dpi_opcode = 0x%02x",
				IR, opcode, dpi_opcode);
			} break;
		case 0x07: {
			const uint opcode7 = mlBFEXT(IR, 27, 24);
			LOG(">> ir = 0x%08x, opcode = 0x%02x, 0x%02x, 20: %01u, 4: %01u",
				IR, opcode, opcode7, BEXT(IR, 20), BEXT(IR, 4));
			} break;
		default:
			LOG(">> ir = 0x%08x, opcode = 0x%02x", IR, opcode);
			break;
	}

	soc_core_disasm_arm(core, IP, IR);
	UNIMPLIMENTED;
}
