#pragma once

static inline void csx_core_arm_decode_rd(csx_core_p core,
	const int get_rd)
{
	csx_core_decode_get(core, rRD, 15, 12, get_rd);
}

static inline void csx_core_arm_decode_rm(csx_core_p core,
	const int get_rm)
{
	csx_core_decode_get(core, rRM, 3, 0, get_rm);
}

static inline void csx_core_arm_decode_rn(csx_core_p core,
	const int get_rn)
{
	csx_core_decode_get(core, rRN, 19, 16, get_rn);
}

static inline void csx_core_arm_decode_rn_rd(csx_core_p core,
	const int get_rn,
	const int get_rd)
{
	csx_core_arm_decode_rn(core, get_rn);
	csx_core_arm_decode_rd(core, get_rd);
}

/* **** */

typedef struct csx_coproc_data_t* csx_coproc_data_p;
typedef struct csx_coproc_data_t {
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
	uint8_t		wb;
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

void csx_core_arm_decode_coproc(csx_core_p core, csx_coproc_data_p acp);
void csx_core_arm_decode_ldst(csx_core_p core, csx_ldst_p ls);
void csx_core_arm_decode_shifter_operand(csx_core_p core, csx_dpi_p dpi);
const char* csx_core_arm_decode_shifter_op_string(uint8_t shopc);
