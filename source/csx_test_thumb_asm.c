#include <stdint.h>

/* **** */

uint32_t __attribute__((target("thumb")))
	_test_thumb_adds_rn_1_asm(uint32_t* p2rd, const uint32_t rn, const uint32_t rm) {
		return(rn + 1);
}

uint32_t __attribute__((target("thumb")))
	_test_thumb_adds_rn_7_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm) {
		return(rn + 7);
}

uint32_t __attribute__((target("thumb")))
	_test_thumb_adds_rn_x_asm(uint32_t n, const uint32_t rn, const uint32_t rm) {

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
}

uint32_t __attribute__((target("thumb")))
	_test_thumb_adds_rn_rm_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm) {
		return(rn + rm);
}

/* **** */

uint32_t __attribute__((target("thumb")))
	_test_thumb_ands_rn_rm_asm(uint32_t rd, const uint32_t rm) {
		return(rd & rm);
}

/* **** */

uint32_t __attribute__((target("thumb")))
	_test_thumb_asrs_rn_rm_asm(int32_t rd, const uint32_t rm) {
		return(rd >> rm);
}

/* **** */

uint32_t __attribute__((target("thumb")))
	_test_thumb_bics_rn_rm_asm(uint32_t rd, const uint32_t rm) {
		return(rd & ~rm);
}

/* **** */

uint32_t __attribute__((target("thumb")))
	_test_thumb_subs_rn_1_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm) {
		return(rn - 1);
}

uint32_t __attribute__((target("thumb")))
	_test_thumb_subs_rn_7_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm) {
		return(rn - 7);
}

uint32_t __attribute__((target("thumb")))
	_test_thumb_subs_rn_rm_asm(uint32_t* rd, const uint32_t rn, const uint32_t rm) {
		return(rn - rm);
}
