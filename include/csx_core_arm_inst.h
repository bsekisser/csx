#define ARM_INST_BIT_LINK			24
#define ARM_INST_BIT_LOAD			20
#define ARM_INST_BIT_R				22

enum {
	_DPI_AND,
	_DPI_EOR,
	_DPI_SUB,
	_DPI_RSB,
	_DPI_ADD,
	_DPI_ADC,
	_DPI_SBC,
	_DPI_RSC,
	_DPI_TST,
	_DPI_TEQ,
	_DPI_CMP,
	_DPI_CMN,
	_DPI_ORR,
	_DPI_MOV,
	_DPI_BIC,
	_DPI_MVN,
};

#define ARM_INST_DPI(_x)			(_DPI_ ## _x << 21)
#define ARM_INST_DPI_MASK			(_BF(27, 26) | _BF(24, 21))


#define ARM_INST_B					(_BV(27) | _BV(25))
#define ARM_INST_B_MASK				_BF(27, 25)
#define ARM_INST_BX					(_BV(24) | _BV(21) | _BV(4))
#define ARM_INST_BX_MASK			(_BF(27, 20) | _BF(7, 4))
#define ARM_INST_BIC				ARM_INST_DPI(BIC)
#define ARM_INST_MCR				(_BF(27, 25) |  _BV(4))
#define ARM_INST_MCR_MASK			(_BF(27, 24) | _BV(20) | _BV(4))
#define ARM_INST_MOV				ARM_INST_DPI(MOV)
#define ARM_INST_MOV_MASK			ARM_INST_DPI_MASK
#define ARM_INST_MRS				_BV(24)
#define ARM_INST_MRS_MASK			(_BF(27, 23) | _BF(21, 20))
#define ARM_INST_MSR				(_BV(24) | _BV(21))
#define ARM_INST_MSR_MASK			((_BF(27, 23) | _BF(21, 20)) & (~_BV(25)))
#define ARM_INST_MVN				ARM_INST_DPI(MVN)
#define ARM_INST_MVN_MASK			ARM_INST_DPI_MASK
#define ARM_INST_ORR				ARM_INST_DPI(ORR)
