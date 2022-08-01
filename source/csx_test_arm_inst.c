#include "csx.h"
#include "csx_core.h"
#include "csx_core_arm_inst.h"
#include "csx_test.h"
#include "csx_test_arm.h"
#include "csx_test_arm_inst.h"

/* arm compiler utilities */

#define COND_EA     0x0e

#define COND(_cc) ((COND_ ## _cc) << 28)

static inline void _c_ea(csx_test_p t, uint32_t value)
{
	csx_p csx = t->csx;

	value |= COND(EA);
	
	if(0) LOG("0x%08x: 0x%08x", t->pc, value);
	
	csx_mmu_write(csx->mmu, t->pc, value, sizeof(uint32_t));
	t->pc += sizeof(uint32_t);
}

/* arm instruction register utilities */

static inline uint32_t _rd(csx_reg_t r)
{
	uint32_t r_out = (r & 0x0f) << 12;

	if(0) LOG("r%02u -> %08x", r, r_out);

	return(r_out);
}

static inline uint32_t _rm(csx_reg_t r)
{
	uint32_t r_out = r & 0x0f;

	if(0) LOG("r%02u -> %08x", r, r_out);

	return(r_out);
}

static inline uint32_t _rn(csx_reg_t r)
{
	uint32_t r_out = (r & 0x0f) << 16;

	if(0) LOG("r%02u -> %08x", r, r_out);

	return(r_out);
}

/* arm instruction utilities */

static void _bxx(csx_test_p t, int32_t offset, int link)
{
	uint32_t opcode = (5 << 25);

	if(link)
		BSET(opcode, ARM_INST_BIT_LINK);

	uint32_t ea = (offset >> 2) & _BM(24);

	if(0) LOG("opcode = 0x%08x, offset = 0x%08x, ea = 0x%08x", opcode, offset, ea);

	_c_ea(t, opcode | ea);
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
	shift = (shift & _BM(15 - 7)) >> 1;
	
	shifter_operand_t out = (shift << 7) | r;
	
	return(out);
}

static void _arm_dp_op_s_rn_rd_sop(csx_test_p t,
	uint32_t opcode,
	uint8_t s,
	csx_reg_t rn,
	csx_reg_t rd,
	shifter_operand_t shopt)
{
	BMAS(opcode, ARM_INST_BIT_S, s);
	
	opcode |= _rn(rn) | _rd(rd);
	
	opcode |= BMOV(shopt, 15, 25);
	opcode |= shopt & _BM(11);
	
	_c_ea(t, opcode);
}


shifter_operand_t arm_dpi_lsl_r_s(uint8_t r, uint8_t shift)
{
	return(_arm_dpi_sop_r_s(CSX_SHIFTER_OP_LSL, r, shift));
}

shifter_operand_t arm_dpi_ror_i_s(uint8_t i, uint8_t shift)
{
	i &= _BM(7);
	shift = (shift & _BM(12 - 8)) >> 1;
	
	shifter_operand_t out = _BV(15) | (shift << 8) | i;

	return(out);
}

/* arm instruction compilers */

void arm_b(csx_test_p t, uint32_t offset)
{
	_bxx(t, offset, 0);
}

void arm_bl(csx_test_p t, uint32_t offset)
{
	_bxx(t, offset, 1);
}

void arm_bx(csx_test_p t, csx_reg_t rm)
{
	uint32_t opcode = _BV(24) | _BV(21) | _MLBF(19, 8) | _BV(4) | _rm(rm);

	_c_ea(t, opcode);
}

void arm_ldr_rn_rd_i(csx_test_p t, csx_reg_t rn, csx_reg_t rd, int32_t offset)
{
	int u = offset > 0;

	uint32_t ea = (u ? offset : 8 - offset) & _BM(11);

	if(0) LOG("rn = %02u, rd = %02u, offset = 0x%08x, ea = 0x%08x", rn, rd, offset, ea);

	/* iPUbwL */
	
	uint32_t opcode = _ldst_ipubwl(0, 1, u, 0, 0, 1);

	opcode |= _rn(rn) | _rd(rd);

	if(0) LOG("opcode = 0x%08x, ea = 0x%08x", opcode, ea);

	_c_ea(t, opcode | ea);
}

void arm_adds_rn_rd_sop(csx_test_p t, csx_reg_t rn, csx_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(ADD), 1, rn, rd, shopt);
}

void arm_mov_rd_sop(csx_test_p t, csx_reg_t rd, shifter_operand_t shopt)
{
	uint32_t opcode = ARM_INST_MOV;
	
	opcode |= _rd(rd);

	opcode |= BMOV(shopt, 15, 25);
	opcode |= shopt & _BM(11);
	
	_c_ea(t, opcode);
}

void arm_str_rn_rd_i(csx_test_p t, csx_reg_t rn, csx_reg_t rd, int32_t offset)
{
	int u = offset > 0;

	uint32_t ea = (u ? offset : 8 - offset) & _BM(11);

	if(0) LOG("rn = %02u, rd = %02u, offset = 0x%08x, ea = 0x%08x", rn, rd, offset, ea);

	/* iPUbwL */
	
	uint32_t opcode = _ldst_ipubwl(0, 1, u, 0, 0, 0);

	opcode |= _rn(rn) | _rd(rd);

	if(0) LOG("opcode = 0x%08x, ea = 0x%08x", opcode, ea);

	_c_ea(t, opcode | ea);
}

void arm_subs_rn_rd_sop(csx_test_p t, csx_reg_t rn, csx_reg_t rd, shifter_operand_t shopt)
{
	_arm_dp_op_s_rn_rd_sop(t, ARM_INST_DPI(SUB), 1, rn, rd, shopt);
}

void arm_swi(csx_test_p t, uint32_t i24)
{
	_c_ea(t, (0x0f << 24) | (i24 & _BM(23)));
}
