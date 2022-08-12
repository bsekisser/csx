void thumb_add_sub_i3_rn_rd(csx_test_p t, uint8_t add_sub, uint8_t imm3, soc_core_reg_t rn, soc_core_reg_t rd);
void thumb_ldmia_rd_reglist(csx_test_p t, soc_core_reg_t rd, uint8_t rlist);
void thumb_stmia_rd_reglist(csx_test_p t, soc_core_reg_t rd, uint8_t rlist);
void thumb_mov_rd_i(csx_test_p t, soc_core_reg_t rd, uint8_t imm8);
void thumb_pop(csx_test_p t, uint8_t rlist);
void thumb_push(csx_test_p t, uint8_t rlist);
