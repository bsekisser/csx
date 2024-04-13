#pragma once

/* **** */

#include "csx_test.h"

/* **** */

#include <stdint.h>

/* **** */

uint32_t csx_test_arm_adcs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_adds_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_ands_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_bics_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_cmp_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_eors_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_rsbs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_rscs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_sbcs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
uint32_t csx_test_arm_subs_asm(csx_test_p t, uint32_t *psr, uint32_t ir0, uint32_t ir1);
