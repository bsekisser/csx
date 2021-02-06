#define _setup_decode_rd(_opcode, _rd) \
	csx_reg_t _rd; \
	csx_core_arm_decode_rd(_opcode, &_rd);

static inline void csx_core_arm_decode_rd(uint32_t opcode, csx_reg_p rd)
{
	if(rd)
		*rd = BFEXT(opcode, 15, 12);
}

#define _setup_decode_rm(_opcode, _rm) \
	csx_reg_t _rm; \
	csx_core_arm_decode_rm(_opcode, &_rm);

static inline void csx_core_arm_decode_rm(uint32_t opcode, csx_reg_p rm)
{
	if(rm)
		*rm = BFEXT(opcode, 3, 0);
}

static inline void csx_core_arm_decode_rn(uint32_t opcode, csx_reg_p rn)
{
	if(rn)
		*rn = BFEXT(opcode, 19, 16);
}

#define _setup_decode_rn_rd(_opcode, _rn, _rd) \
	csx_reg_t _rn \
	csx_reg_t _rd; \
	csx_core_arm_decode_rn_rd(_opcode, &_rn, &_rd);

static inline void csx_core_arm_decode_rn_rd(uint32_t opcode, csx_reg_p rn, csx_reg_p rd)
{
	csx_core_arm_decode_rn(opcode, rn);
	csx_core_arm_decode_rd(opcode, rd);
}

/* **** */

typedef struct csx_coproc_data_t* csx_coproc_data_p;
typedef struct csx_coproc_data_t {
	csx_reg_t		rd;
	uint32_t		rd_v;

	csx_reg_t		crn;
	uint32_t		crn_v;
	csx_reg_t		crm;
	uint32_t		crm_v;
	
	uint8_t			opcode1;
	uint8_t			opcode2;
	uint8_t			cp_num;
	
	struct	{
		uint8_t		l;
		uint8_t		x4;
	}bit;
}csx_coproc_data_t;

typedef struct csx_ldst_t* csx_ldst_p;
typedef struct csx_ldst_t {
	csx_reg_t	rd;
	uint32_t	rd_v;

	csx_reg_t	rn;
	uint32_t	rn_v;
	csx_reg_t	rm;
	uint32_t	rm_v;
	
	uint32_t	ea;

	uint8_t		ldstx;

	uint8_t		rw_size;

	uint8_t		shift_imm;
	uint8_t		shift;
	
	struct {
		uint8_t		s;		/*	signed */
	}flags;
	
	struct {
		uint8_t		p;
		uint8_t		u;
		union {
			uint8_t		bit22;
			uint8_t		i22;
			uint8_t		b22;
			uint8_t		s22;
		};
		uint8_t		w;
		uint8_t		l;
		uint8_t		s6;
		uint8_t		h;
	}bit;
}csx_ldst_t;

typedef struct csx_dpi_t* csx_dpi_p;
typedef struct csx_dpi_t {
	csx_reg_t	rd;
	uint32_t	rd_v;

	uint8_t		wb;

	csx_reg_t	rn;
	uint32_t	rn_v;
	csx_reg_t	rm;
	uint32_t	rm_v;	/* or immediate value */
	csx_reg_t	rs;
	uint32_t	rs_v;	/* or imediate shift */

	uint8_t		operation;

	uint8_t		shift_op;

	struct {
		uint8_t		i;
		uint8_t		s;
		uint8_t		x7;
		uint8_t		x4;
	}bit;

	struct {
		uint8_t		c;
		uint32_t	v;
	}out;

	const char*		mnemonic;
	char			op_string[256];
}csx_dpi_t;

enum {
	CSX_SHIFTER_OP_LSL,
	CSX_SHIFTER_OP_LSR,
	CSX_SHIFTER_OP_ASR,
	CSX_SHIFTER_OP_ROR,
};

/* **** */

void csx_core_arm_decode_coproc(csx_core_p core, uint32_t opcode, csx_coproc_data_p acp);
void csx_core_arm_decode_ldst(csx_core_p core, uint32_t opcode, csx_ldst_p ls);
void csx_core_arm_decode_shifter_operand(csx_core_p core, uint32_t opcode, csx_dpi_p dpi);
const char* csx_core_arm_decode_shifter_op_string(uint8_t shopc);
