#define SOC_CORE_THUMB_ADD_RD_PCSP_I				(_BV(15) | _BV(13))
#define SOC_CORE_THUMB_ADD_RD_PCSP_I_MASK			mlBF(15, 12)
#define SOC_CORE_THUMB_ADD_SUB_RN_RD				mlBF(12, 11)
#define SOC_CORE_THUMB_ADD_SUB_RN_RD_MASK			mlBF(15, 11)
#define SOC_CORE_THUMB_ADD_SUB_SP_I7				(_BV(15) | mlBF(13, 12))
#define SOC_CORE_THUMB_ADD_SUB_SP_I7_MASK			mlBF(15, 8)
#define SOC_CORE_THUMB_ASCM_RD_I8(_operation)		mlBFINS(_BV(13), _operation, 12, 11)
#define SOC_CORE_THUMB_ASCM_RD_I8_MASK				mlBF(15, 13)
#define SOC_CORE_THUMB_BX							(_BV(14) | mlBF(10, 8))
#define SOC_CORE_THUMB_BX_MASK						mlBF(15, 8)
#define SOC_CORE_THUMB_DP_RMS_RDN					_BV(14)
#define SOC_CORE_THUMB_DP_RMS_RDN_MASK				mlBF(15, 10)
#define SOC_CORE_THUMB_LDST_BW_O_RN_RD				mlBF(14, 13)
#define SOC_CORE_THUMB_LDST_BW_O_RN_RD_MASK			mlBF(15, 13)
#define SOC_CORE_THUMB_LDST_H_O_RN_RD				_BV(15)
#define SOC_CORE_THUMB_LDST_H_O_RN_RD_MASK			mlBF(15, 12)
#define SOC_CORE_THUMB_LDST_PC_RD_I					_BV(14)
#define SOC_CORE_THUMB_LDST_PC_RD_I_MASK			mlBF(15, 12)
#define SOC_CORE_THUMB_LDST_RM_RN_RD				(_BV(14) | _BV(12))
#define SOC_CORE_THUMB_LDST_RM_RN_RD_MASK			mlBF(15, 12)
#define SOC_CORE_THUMB_LDST_SP_RD_I					(_BV(15) | _BV(12))
#define SOC_CORE_THUMB_LDST_SP_RD_I_MASK			mlBF(15, 12)
#define SOC_CORE_THUMB_LDSTM_RN_RXX(_bit_l)			mlBFINS(mlBF(15, 14), _bit_l, 11, 11) 
#define SOC_CORE_THUMB_LDSTM_RN_RXX_MASK			mlBF(15, 12)
#define SOC_CORE_THUMB_POP_PUSH(_bit_l)				mlBFINS(_BV(15) | mlBF(13, 12) | _BV(10), _bit_l, 11, 11)
#define SOC_CORE_THUMB_POP_PUSH_MASK				(mlBF(15, 12) | mlBF(10, 9))
#define SOC_CORE_THUMB_SBI_IMM5_RM_RD				0
#define SOC_CORE_THUMB_SBI_IMM5_RM_RD_MASK			mlBF(15, 13)
#define SOC_CORE_THUMB_SDP_RMS_RDN(_operation)		mlBFINS((_BV(14) | _BV(10)), _operation, 9, 8)
#define SOC_CORE_THUMB_SDP_RMS_RDN_MASK				mlBF(15, 10)

/* **** */

#define SOC_CORE_THUMB_ADD_RD_I						SOC_CORE_THUMB_ASCM_RD_I8(THUMB_ASCM_OP_ADD)
#define SOC_CORE_THUMB_MOV_RD_I						SOC_CORE_THUMB_ASCM_RD_I8(THUMB_ASCM_OP_MOV)
#define SOC_CORE_THUMB_SUB_RD_I						SOC_CORE_THUMB_ASCM_RD_I8(THUMB_ASCM_OP_SUB)

/* **** */

enum {
	THUMB_ASCM_OP_MOV = 0x00,
	THUMB_ASCM_OP_CMP = 0x01,
	THUMB_ASCM_OP_ADD = 0x02,
	THUMB_ASCM_OP_SUB = 0x03,
};

enum {
	THUMB_SBI_OP_LSL = 0x00,
	THUMB_SBI_OP_LSR = 0x01,
	THUMB_SBI_OP_ASR = 0x02,
};

enum {
	THUMB_SDP_OP_ADD = 0x00,
	THUMB_SDP_OP_CMP = 0x01,
	THUMB_SDP_OP_MOV = 0x02,
};

enum {
	THUMB_DP_OP_AND,
	THUMB_DP_OP_LSL = 0x02,
//	THUMB_DP_OP_LSR = 0x03,
	THUMB_DP_OP_TST = 0x08,
	THUMB_DP_OP_NEG = 0x09,
	THUMB_DP_OP_CMP = 0x0a,
	THUMB_DP_OP_CMN = 0x0b,
	THUMB_DP_OP_ORR = 0x0c,
	THUMB_DP_OP_MUL = 0x0d,
	THUMB_DP_OP_BIC = 0x0e,
	THUMB_DP_OP_MVN = 0x0f,
};
