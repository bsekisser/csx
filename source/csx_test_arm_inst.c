#include "csx_test_arm_inst.h"
#include "soc_core_arm_inst.h"

#include "soc_core_disasm.h"

#include "csx_test_utility.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

/* arm compiler utilities */

#define COND_AL     0x0e
#define COND_NV		0x0f

#define COND(_cc) ((COND_ ## _cc) << 28)

static inline void _c_cc(csx_test_p t, unsigned cc, uint32_t value)
{
	value |= ((cc & 0x0f) << 28);
	
	if(0) LOG("0x%08x: 0x%08x", t->pc, value);
	
	_cxx(t, value, sizeof(uint32_t));
}

static inline void _c_al(csx_test_p t, uint32_t value)
{
	_c_cc(t, COND_AL, value);
}

/* arm instruction register utilities */

static inline uint32_t _rd(soc_core_reg_t r)
{
	uint32_t r_out = (r & 0x0f) << 12;

	if(0) LOG("r%02u -> %08x", r, r_out);

	return(r_out);
}

static inline uint32_t _rm(soc_core_reg_t r)
{
	uint32_t r_out = r & 0x0f;

	if(0) LOG("r%02u -> %08x", r, r_out);

	return(r_out);
}

static inline uint32_t _rn(soc_core_reg_t r)
{
	uint32_t r_out = (r & 0x0f) << 16;

	if(0) LOG("r%02u -> %08x", r, r_out);

	return(r_out);
}

/* arm instruction utilities */

static void _bcc(csx_test_p t, unsigned cc, int32_t offset, int link)
{
	uint32_t opcode = (5 << 25);

	if(link)
		BSET(opcode, ARM_INST_BIT_LINK);

	uint32_t ea = (offset >> 2) & _BM(24);

	if(0) LOG("opcode = 0x%08x, offset = 0x%08x, ea = 0x%08x", opcode, offset, ea);

	_c_cc(t, cc, opcode | ea);
}

static void _bcc_al(csx_test_p t, int32_t offset, int link)
{
	_bcc(t, COND_AL, offset, link);
}

static inline uint32_t _ldst_ipubwl(uint8_t i, uint8_t p, uint8_t u, uint8_t b, uint8_t w, uint8_t l)
{
	uint32_t opcode = _BV(26);
	
	opcode |= i ? _BV(25) : 0;
	opcode |= p ? _BV(24) : 0;
	opcode |= u ? _BV(23) : 0;
	opcode |= b ? _BV(22) : 0;
	opcode |= w ? _BV(21) : 0;
	opcode |= l ? _BV(20) : 0;

	return(opcode);
}

static shifter_operand_t _arm_dpi_sop_r_s(uint8_t sop, uint8_t r, uint8_t shift)
{
	shift &= _BM(1 + (11 - 7));
//	shift >>= 1;
	
	shifter_operand_t out = (shift << 7) | ((sop & 3) << 5) | (r & 0x0f);
	
	return(out);
}

static uint32_t _arm_dp_op_s_rn_rd_sop(csx_test_p t,
	uint32_t opcode,
	uint8_t s,
	soc_core_reg_t rn,
	soc_core_reg_t rd,
	shifter_operand_t shopt)
{
	BMAS(opcode, ARM_INST_BIT_S, !!s);
	
	opcode |= _rn(rn) | _rd(rd);
	
	opcode |= BMOV(shopt, 15, 25);
	opcode |= shopt & _BM(12);
	
	_c_al(t, opcode);
	return(opcode);
}

shifter_operand_t arm_dpi_asr_r_s(uint8_t r, uint8_t shift)
{
	return(_arm_dpi_sop_r_s(SOC_CORE_SHIFTER_OP_ASR, r, shift));
}

shifter_operand_t arm_dpi_lsl_r_s(uint8_t r, uint8_t shift)
{
	return(_arm_dpi_sop_r_s(SOC_CORE_SHIFTER_OP_LSL, r, shift));
}

shifter_operand_t arm_dpi_lsr_r_s(uint8_t r, uint8_t shift)
{
	return(_arm_dpi_sop_r_s(SOC_CORE_SHIFTER_OP_LSR, r, shift));
}

shifter_operand_t arm_dpi_ror_i_s(uint8_t i, uint8_t shift)
{
	i &= _BM(1 + (7 - 0));

	shift >>= 1;
	shift &= _BM(1 + (11 - 8));
	
	shifter_operand_t out = _BV(15) | (shift << 8) | i;

	if(0) LOG("i = 0x%08x, shift = 0x%08x, shifter_operand = 0x%08x", i, shift, out);

	return(out);
}

/* arm instruction compilers */

void arm_b(csx_test_p t, uint32_t offset)
{
	_bcc_al(t, offset, 0);
}

void arm_bl(csx_test_p t, uint32_t offset)
{
	_bcc_al(t, offset, 1);
}

void arm_blx(csx_test_p t, uint32_t offset)
{
	_bcc(t, COND_NV, offset, (offset >> 1) & 1);
}

void arm_bx(csx_test_p t, soc_core_reg_t rm)
{
	uint32_t opcode = _BV(24) | _BV(21) | mlBF(19, 8) | _BV(4) | _rm(rm);

	_c_al(t, opcode);
}

void arm_ldr_rn_rd_i(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, int32_t offset)
{
	int u = offset > 0;

	uint32_t ea = (u ? offset : 8 - offset) & _BM(11);

	if(0) LOG("rn = %02u, rd = %02u, offset = 0x%08x, ea = 0x%08x", rn, rd, offset, ea);

	/* iPUbwL */
	
	uint32_t opcode = _ldst_ipubwl(0, 1, u, 0, 0, 1);

	opcode |= _rn(rn) | _rd(rd);

	if(0) LOG("opcode = 0x%08x, ea = 0x%08x", opcode, ea);

	_c_al(t, opcode | ea);
}

void arm_adcs_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(ADC), 1, rn, rd, shopt);
}

void arm_add_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(ADD), 0, rn, rd, shopt);
}

void arm_adds_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(ADD), 1, rn, rd, shopt);
}

void arm_ands_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(AND), 1, rn, rd, shopt);
}

void arm_asr_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, unsigned shift)
{
	arm_mov_rd_sop(t, rd, arm_dpi_asr_r_s(rm, shift));
}

void arm_asrs_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, unsigned shift)
{
	arm_movs_rd_sop(t, rd, arm_dpi_asr_r_s(rm, shift));
}

void arm_bics_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(BIC), 1, rn, rd, shopt);
}

void arm_cmps_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(CMP), 1, rn, rd, shopt);
}

void arm_eors_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(EOR), 1, rn, rd, shopt);
}

void arm_lsl_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, unsigned shift)
{
	arm_mov_rd_sop(t, rd, arm_dpi_lsl_r_s(rm, shift));
}

void arm_lsls_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, unsigned shift)
{
	arm_movs_rd_sop(t, rd, arm_dpi_lsl_r_s(rm, shift));
}

void arm_lsr_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, unsigned shift)
{
	arm_mov_rd_sop(t, rd, arm_dpi_lsr_r_s(rm, shift));
}

void arm_lsrs_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, unsigned shift)
{
	arm_movs_rd_sop(t, rd, arm_dpi_lsr_r_s(rm, shift));
}

void arm_mov_rd_imm(csx_test_p t, soc_core_reg_t rd, uint8_t imm)
{
	arm_mov_rd_sop(t, rd, arm_dpi_ror_i_s(imm, 0));
}

void arm_mov_rd_sop(csx_test_p t, soc_core_reg_t rd, shifter_operand_t shopt)
{
	uint32_t opcode = _arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(MOV), 0, 0, rd, shopt);

	if(0)
		soc_core_disasm_arm(t->core, 0, opcode);
}

void arm_movs_rd_imm(csx_test_p t, soc_core_reg_t rd, uint8_t imm)
{
	arm_movs_rd_sop(t, rd, arm_dpi_ror_i_s(imm, 0));
}

void arm_movs_rd_sop(csx_test_p t, soc_core_reg_t rd, shifter_operand_t shopt)
{
	
	uint32_t opcode = _arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(MOV), 1, 0, rd, shopt);

	if(0)
		soc_core_disasm_arm(t->core, 0, opcode);
}

void arm_ror_rd_imm_is(csx_test_p t, soc_core_reg_t rd, uint8_t imm, unsigned shift)
{
	arm_mov_rd_sop(t, rd, arm_dpi_ror_i_s(imm, shift));
}

void arm_rors_rd_imm_is(csx_test_p t, soc_core_reg_t rd, uint8_t imm, unsigned shift)
{
	arm_movs_rd_sop(t, rd, arm_dpi_ror_i_s(imm, shift));
}

void arm_rsb_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(RSB), 0, rn, rd, shopt);
}

void arm_str_rn_rd_i(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, int32_t offset)
{
	int u = offset > 0;

	uint32_t ea = (u ? offset : 8 - offset) & _BM(11);

	if(0) LOG("rn = %02u, rd = %02u, offset = 0x%08x, ea = 0x%08x", rn, rd, offset, ea);

	/* iPUbwL */
	
	uint32_t opcode = _ldst_ipubwl(0, 1, u, 0, 0, 0);

	opcode |= _rn(rn) | _rd(rd);

	if(0) LOG("opcode = 0x%08x, ea = 0x%08x", opcode, ea);

	_c_al(t, opcode | ea);
}

void arm_sub_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(SUB), 0, rn, rd, shopt);
}

void arm_subs_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(SUB), 1, rn, rd, shopt);
}

void arm_swi(csx_test_p t, uint32_t i24)
{
	_c_al(t, (0x0f << 24) | (i24 & _BM(23)));
}
