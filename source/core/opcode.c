/* name, set, clear */

#define INST0(_x0)		(((_x0) & 0x03) << 26)
#define INST1(_x1)		(((_x1) & 0x07) << 25)


#define CSX_INST1_LDST		_INST1(0x2)

#define CSX_INST2_B			_INST1(0x5)

#define CSX_INST3_AND		_INST1_2(0x0, 0x0)
#define CSX_INST3_SUB		_INST1_2(0x0, 0x2)
#define CSX_INST3_MRS		_INST1_2(0x0, 0x8)
#define CSX_INST3_CMP		_INST1_2(0x0, 0xa)
#define CSX_INST3_ORR		_INST1_2(0x0, 0xc)
#define CSX_INST3_MOV		_INST1_2(0x0, 0xd)
#define CSX_INST3_BIC		_INST1_2(0x0, 0xe)
#define CSX_INST3_MVN		_INST1_2(0x0, 0xf)

OPCODE(b, INST1(5), ~INST1(5))
OPCODE(bl, INST1(5) | _BV(24), ~INST1(5))

#define _BV(_bit)			(1ULL << (_bit))
#define _BVM(_bit)			(_BV(((_bit) + 1) - 1)

#define _BF(_msb, _lsb)		(_BVM(_msb) & (~_BVM(_lsb)))

#define CC					_BF(31, 28)

#define OPCODE				_BF(24, 21)

#define MASK				_BF(15, 12)
#define ROTATE				_BF(11, 8)
#define SHIFT_AMOUNT		_BF(11, 7)
#define SHIFT				_BF(6, 5)


#define Rd					_BF(15, 12)
#define Rm					_BF(3, 0)
#define Rn					_BF(19, 16)
#define	Rs					_BF(11, 8)

#define IMMEDIATE11			_BF(11, 0)
#define IMMEDIATE7			_BF(7, 0)

#define _P					_BV(24)
#define _U					_BV(23)
#define _B					_BV(22)
#define _R					_BV(22)
#define _W					_BV(21)
#define _L					_BV(20)
#define	_S					_BV(20)

#define OPCODE_S_RnRd_SHIFT_Rm \
	OPCODE _S Rn Rd SHIFT_AMOUNT SHIFT Rm

#define PUBWL				((_P) (_U) (_B) (_W) (_L))

0011010
