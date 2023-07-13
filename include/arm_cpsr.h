#pragma once

/* **** */

enum {
	_CPSR_C_BIT_T = 5,
	_CPSR_C_BIT_F = 6,
	_CPSR_C_BIT_I = 7,
	_CPSR_C_BIT_A = 8,
	_CPSR_C_BIT_E = 9,
	
	_CPSR_C_BIT_Abort = _CPSR_C_BIT_A,
	_CPSR_C_BIT_FIQ = _CPSR_C_BIT_F,
	_CPSR_C_BIT_IRQ = _CPSR_C_BIT_I,
	_CPSR_C_BIT_Thumb = _CPSR_C_BIT_T,
};

#define CPSR_C(_x) _BV(_CPSR_C_BIT_##_x)
#define IF_CPSR_C(_x) (CPSR_C(_x) & CPSR)

enum {
	_CPSR_M_User,
	_CPSR_M_FIQ,
	_CPSR_M_IRQ,
	_CPSR_M_Supervisor,
//
	_CPSR_M_32 = 0x10,
//
	_CPSR_M_Abort = 0x17,
	_CPSR_M_Undefined = 0x18 | 3,
	_CPSR_M_System = 0x1f,
};

#define __CPSR_M(_x) (_CPSR_M_##_x)

#define CPSR_M26(_x) __CPSR_M(_x)
#define CPSR_M32(_x) (__CPSR_M(32) | __CPSR_M(_x))

#define CPSR_M(_x) ((_CPSR_M_##_x) & 0x1f)
