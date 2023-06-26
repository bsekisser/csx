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
	_CPSR_M_User = 0x10,
	_CPSR_M_FIQ = 0x11,
	_CPSR_M_IRQ = 0x12,
	_CPSR_M_Supervisor = 0x13,
	_CPSR_M_Abort = 0x17,
	_CPSR_M_Undefined = 0x18 | 3,
	_CPSR_M_System = 0x1f,
};

#define CPSR_M(_x) ((_CPSR_M_##_x) & 0x1f)
