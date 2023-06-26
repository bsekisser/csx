#pragma once

/* **** */

enum {
	_cp15_reg1_m = 0,
	_cp15_reg1_a = 1,
	_cp15_reg1_b = 7,
	_cp15_reg1_r = 9,
	_cp15_reg1_v = 13,
	_cp15_reg1_l4 = 15,
	_cp15_reg1_dt = 16,
	_cp15_reg1_it = 18,
	_cp15_reg1_u = 22,
	_cp15_reg1_ve = 24,
	_cp15_reg1_ee = 25,
};

#define _CP15_reg1(_x) _cp15_reg1_##_x
#define _CP15_reg1_bit(_x) _BV(_CP15_reg1(_x))

#define CP15_reg1_bit(_x)			BEXT(csx->cp15_reg1, _CP15_reg1(_x))
#define CP15_reg1_clear(_x)			BCLR(csx->cp15_reg1, _CP15_reg1(_x))
#define CP15_reg1_set(_x) 			BSET(csx->cp15_reg1, _CP15_reg1(_x))
#define CP15_reg1_test(_x) 			BTST(csx->cp15_reg1, _CP15_reg1(_x))

#define CP15_reg1_AbitOrUbit (CP15_reg1_bit(a) || CP15_reg1_bit(u))
