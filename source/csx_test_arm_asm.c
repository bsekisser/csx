#include "unused.h"

#ifndef uint
	typedef long int sint;
	typedef unsigned long int uint;
#endif

enum {
	_asr,
	_lsl,
	_lsr,
	_ror,
};

//#define THUMB __attribute__((target("thumb")))
#define THUMB

static THUMB uint _shift_operand_asr(uint rd, const uint rn, const sint rm, const uint rs) {
	return(rm >> rs);

	UNUSED(rd, rn);
}

static THUMB uint _shift_operand_lsl(uint rd, const uint rn, const uint rm, const uint rs) {
	return(rm << rs);

	UNUSED(rd, rn);
}

static THUMB uint _shift_operand_lsr(uint rd, const uint rn, const uint rm, const uint rs) {
	return(rm >> rs);

	UNUSED(rd, rn);
}

static THUMB uint _shift_operand_ror(uint rd, const uint rn, const uint rm, const uint rs) {
	const uint lhs = rm << ((sizeof(rm) << 3) - rs);
	const uint rhs = rm >> rs;

	return(lhs | rhs);

	UNUSED(rd, rn);
}

UNUSED_FN static THUMB uint _shift_operand(
	uint rd,
	const uint rn, const uint rm, const uint rs,
	const uint shift)
{
	if(rs) {
		switch(shift) {
			case _asr:
				return(_shift_operand_asr(rd, rn, rm, rs));
			case _lsl:
				return(_shift_operand_lsl(rd, rn, rm, rs));
			case _lsr:
				return(_shift_operand_lsr(rd, rn, rm, rs));
			case _ror:
				return(_shift_operand_ror(rd, rn, rm, rs));
		}
	}

	return(rm);
}

#define ARM_ALU_OP(_name, _action) \
	ARM_ALU_OP_RM(_name, _action, rm)
	
#define ARM_ALU_OP_ACTION(_name, _action) \
	THUMB uint arm_##_name(uint rd, const uint rn, const uint rm) { \
		rd = _action; \
		\
		return(rd); \
	} \
	\
	ARM_ALU_OP_SHIFT_ACTION(_name, _asr, _action) \
	ARM_ALU_OP_SHIFT_ACTION(_name, _lsl, _action) \
	ARM_ALU_OP_SHIFT_ACTION(_name, _lsr, _action) \
	ARM_ALU_OP_SHIFT_ACTION(_name, _ror, _action)

#define ARM_ALU_OP_RM(_name, _action, _rm) \
	ARM_ALU_OP_ACTION(_name, (rn _action _rm))

#define ARM_ALU_OP_SHIFT_ACTION(_name, _shift, _action) \
	THUMB uint arm_##_name##_shift(uint rd, const uint rn, const uint _rm_v, const uint rs) { \
		const uint rm = _shift_operand##_shift(rd, rn, _rm_v, rs); \
		\
		rd = _action; \
		\
		return(rd); \
	}

#define ARM_ALU_SHIFT_OP_ACTION(_name, _action) \
	THUMB uint arm_##_name##_shift(uint rd, const uint rn, const uint _rm_v, const uint rs, const uint shift) { \
		const uint rm = _shift_operand(rd, rn, _rm_v, rs, shift); \
		\
		rd = _action; \
		\
		return(rd); \
	}

#define ARM_ALU_SHIFT_OP(_name, _action) \
	ARM_ALU_SHIFT_OP_RM(_name, _action, rm)

#define ARM_ALU_SHIFT_OP_RM(_name, _action, _rm) \
	ARM_ALU_SHIFT_OP_ACTION(_name, (rn _action _rm))

ARM_ALU_OP(add, +)
//ARM_ALU_SHIFT_OP(add, +)
ARM_ALU_OP(and, &)
//ARM_ALU_SHIFT_OP(and, &)
ARM_ALU_OP_RM(bic, &, ~rm)
//ARM_ALU_SHIFT_OP_RM(bic, &, ~rm)
ARM_ALU_OP(eor, ^)
//ARM_ALU_SHIFT_OP(eor, ^)
ARM_ALU_OP_ACTION(mov, rm; (void)rn)
ARM_ALU_OP_ACTION(nand, ~(rm & rn))
ARM_ALU_OP_ACTION(norr, ~(rm | rn))
ARM_ALU_OP(orr, |)
//ARM_ALU_SHIFT_OP(orr, |)
ARM_ALU_OP_ACTION(rsb, rm - rn)
//ARM_ALU_SHIFT_OP_ACTION(rsb, rm - rn)
ARM_ALU_OP(sub, -)
//ARM_ALU_SHIFT_OP(sub, -)
