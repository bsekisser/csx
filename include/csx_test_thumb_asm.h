#pragma once

/* **** */

#define __CSX_TEST_THUMB_ASM_H__

/* **** */

#include <stdint.h>

/* **** */

uint32_t _test_thumb_adds_rn_1_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm);
uint32_t _test_thumb_adds_rn_7_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm);
uint32_t _test_thumb_adds_rn_rm_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm);

/* **** */

uint32_t _test_thumb_subs_rn_1_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm);
uint32_t _test_thumb_subs_rn_7_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm);
uint32_t _test_thumb_subs_rn_rm_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm);
