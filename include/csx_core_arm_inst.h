#define ARM_INST_BIT_LINK			24
#define ARM_INST_BIT_LOAD			20
#define ARM_INST_BIT_R				22

enum {
	ARM_DPI_OPERATION_AND,
	ARM_DPI_OPERATION_EOR,
	ARM_DPI_OPERATION_SUB,
	ARM_DPI_OPERATION_RSB,

	ARM_DPI_OPERATION_ADD,
	ARM_DPI_OPERATION_ADC,
	ARM_DPI_OPERATION_SBC,
	ARM_DPI_OPERATION_RSC,

	ARM_DPI_OPERATION_TST,
	ARM_DPI_OPERATION_TEQ,
	ARM_DPI_OPERATION_CMP,
	ARM_DPI_OPERATION_CMN,

	ARM_DPI_OPERATION_ORR,
	ARM_DPI_OPERATION_MOV,
	ARM_DPI_OPERATION_BIC,
	ARM_DPI_OPERATION_MVN,
};

#define ARM_INST_DP					0
#define ARM_INST_DP_MASK			_BF(27, 26)
#define ARM_INST_LDST_O11			_BV(26)
#define ARM_INST_LDST_O11_MASK		_BF(27, 25)
#define ARM_INST_LDSTM				_BV(27)
#define ARM_INST_LDSTM_MASK			_BF(27, 25)


#define ARM_INST_DPI(_x)			(ARM_DPI_OPERATION_ ## _x << 21)
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
