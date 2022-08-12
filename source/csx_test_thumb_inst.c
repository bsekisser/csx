#include "csx.h"
#include "soc_core.h"

#include "soc_core_thumb_inst.h"

#include "csx_test.h"
#include "csx_test_utility.h"

#include "csx_test_thumb_inst.h"

void thumb_add_sub_i3_rn_rd(csx_test_p t, uint8_t add_sub, uint8_t imm3, soc_core_reg_t rn, soc_core_reg_t rd)
{
	uint32_t opcode = CSX_CORE_THUMB_ADD_SUB_RN_RD;
	
	opcode |= _BV(10);
	opcode |= BMOV(!!add_sub, 0, 9);
	
	opcode = mlBFINS(opcode, imm3, 8, 6);
	opcode = mlBFINS(opcode, rn, 5, 3);
	opcode = mlBFINS(opcode, rd, 2, 0);
	
	_cxx(t, opcode, sizeof(uint16_t));
}

static void _thumb_ldstmia_rd_reglist(csx_test_p t, uint8_t bit_l, soc_core_reg_t rd, uint8_t rlist)
{
	uint32_t opcode = CSX_CORE_THUMB_LDSTM_RN_RXX(bit_l);
	
	opcode = mlBFINS(opcode, rd, 10, 8);
	opcode = mlBFINS(opcode, rlist, 7, 0);

	_cxx(t, opcode, sizeof(uint16_t));
}

void thumb_ldmia_rd_reglist(csx_test_p t, soc_core_reg_t rd, uint8_t rlist)
{
	_thumb_ldstmia_rd_reglist(t, 1, rd, rlist);
}

void thumb_stmia_rd_reglist(csx_test_p t, soc_core_reg_t rd, uint8_t rlist)
{
	_thumb_ldstmia_rd_reglist(t, 0, rd, rlist);
}

void thumb_mov_rd_i(csx_test_p t, soc_core_reg_t rd, uint8_t imm8)
{
	uint32_t opcode = CSX_CORE_THUMB_MOV_RD_I;
	
	opcode = mlBFINS(opcode, rd, 10, 8);
	opcode = mlBFINS(opcode, imm8, 7, 0);
	
	_cxx(t, opcode, sizeof(uint16_t));
}
