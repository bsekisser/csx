#pragma once

/* **** */

#include "csx_test.h"

#include "soc_core_reg.h"
#include "soc_core_shifter.h"

/* **** */

shifter_operand_t arm_dpi_asr_r_s(uint8_t r, uint8_t shift);
shifter_operand_t arm_dpi_lsl_r_s(uint8_t r, uint8_t shift);
shifter_operand_t arm_dpi_lsr_r_s(uint8_t r, uint8_t shift);
shifter_operand_t arm_dpi_ror_i_s(uint8_t i, uint8_t shift);

/* **** */

void arm_adcs_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_add_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_adds_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_ands_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_asr_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, uint shift);
void arm_asrs_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, uint shift);
void arm_b(csx_test_p t, uint32_t offset);
void arm_bics_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_bl(csx_test_p t, uint32_t offset);
void arm_blx(csx_test_p t, uint32_t offset);
void arm_bx(csx_test_p t, soc_core_reg_t rm);
void arm_cmps_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_eors_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_ldr_rn_rd_i(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, int32_t offset);
void arm_lsl_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, uint shift);
void arm_lsls_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, uint shift);
void arm_lsr_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, uint shift);
void arm_lsrs_rd_rm_is(csx_test_p t, soc_core_reg_t rd, soc_core_reg_t rm, uint shift);
void arm_mov_rd_sop(csx_test_p t, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_movs_rd_sop(csx_test_p t, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_ror_rd_imm_is(csx_test_p t, soc_core_reg_t rd, uint8_t imm, uint shift);
void arm_rsb_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_str_rn_rd_i(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, int32_t offset);
void arm_sub_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_subs_rn_rd_sop(csx_test_p t, soc_core_reg_t rn, soc_core_reg_t rd, shifter_operand_t shopt);
void arm_swi(csx_test_p t, uint32_t i24);
