#include "unused.h"

/* **** */

#include <stdint.h>

/* **** */

#if defined(__arm__) & !defined(__aarch64__)
	#define THUMB __attribute__((target("thumb")))
#else
	#define THUMB
#endif

extern inline THUMB
uint32_t _test_thumb_adds_rn_1_asm(uint32_t* p2rd, const uint32_t rn, const uint32_t rm) {
		return(rn + 1);

	UNUSED(p2rd, rm);
}

extern inline THUMB
uint32_t _test_thumb_adds_rn_7_asm(uint32_t* p2rd, const uint32_t rn, const uint32_t rm) {
		return(rn + 7);

	UNUSED(p2rd, rm);
}

static inline THUMB
uint32_t _test_thumb_adds_rn_x_asm(uint32_t n, const uint32_t rn, const uint32_t rm) {

	switch(n) {
		case 0x01:
			return(rn + 1);
		case 0x02:
			return(rn + 2);
		case 0x03:
			return(rn + 3);
		case 0x04:
			return(rn + 4);
		case 0x05:
			return(rn + 5);
		case 0x06:
			return(rn + 6);
		case 0x07:
			return(rn + 7);
	}

	return(0);

	UNUSED(rm);
}

static inline THUMB
uint32_t _test_thumb_adds_rn_rm_asm(uint32_t* p2rd, const uint32_t rn, const uint32_t rm) {
		return(rn + rm);

	UNUSED(p2rd);
}

/* **** */

static inline THUMB
uint32_t _test_thumb_ands_rn_rm_asm(uint32_t rd, const uint32_t rm) {
		return(rd & rm);
}

/* **** */

static inline THUMB
uint32_t _test_thumb_asrs_rn_rm_asm(int32_t rd, const uint32_t rm) {
		return(rd >> rm);
}

/* **** */

static inline THUMB
uint32_t _test_thumb_bics_rn_rm_asm(uint32_t rd, const uint32_t rm) {
		return(rd & ~rm);
}

/* **** */

static inline THUMB
uint32_t _test_thumb_subs_rn_1_asm(uint32_t* p2rd, const uint32_t rn, const uint32_t rm) {
		return(rn - 1);

	UNUSED(p2rd, rm);
}

static inline THUMB
uint32_t _test_thumb_subs_rn_7_asm(uint32_t* p2rd, const uint32_t rn, const uint32_t rm) {
		return(rn - 7);

	UNUSED(p2rd, rm);
}

static inline THUMB
uint32_t _test_thumb_subs_rn_rm_asm(uint32_t* p2rd, const uint32_t rn, const uint32_t rm) {
		return(rn - rm);

	UNUSED(p2rd);
}
