#pragma once

static inline void soc_core_arm_decode_rd(soc_core_p core,
	const int get_rd)
{
	soc_core_decode_get(core, rRD, 15, 12, get_rd);
}

static inline void soc_core_arm_decode_rm(soc_core_p core,
	const int get_rm)
{
	soc_core_decode_get(core, rRM, 3, 0, get_rm);
}

static inline void soc_core_arm_decode_rn(soc_core_p core,
	const int get_rn)
{
	soc_core_decode_get(core, rRN, 19, 16, get_rn);
}

static inline void soc_core_arm_decode_rn_rd(soc_core_p core,
	const int get_rn,
	const int get_rd)
{
	soc_core_arm_decode_rn(core, get_rn);
	soc_core_arm_decode_rd(core, get_rd);
}

/* **** */

typedef struct soc_coprocessor_t* soc_coprocessor_p;
typedef struct soc_coprocessor_t {
	uint8_t			opcode1;
	uint8_t			opcode2;
	uint8_t			cp_num;
	
	struct	{
		uint8_t		l;
		uint8_t		x4;
	}bit;
}soc_coprocessor_t;

typedef struct soc_core_ldst_t* soc_core_ldst_p;
typedef struct soc_core_ldst_t {
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
}soc_core_ldst_t;

typedef struct soc_core_dpi_t* soc_core_dpi_p;
typedef struct soc_core_dpi_t {
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
}soc_core_dpi_t;

enum {
	CSX_SHIFTER_OP_LSL,
	CSX_SHIFTER_OP_LSR,
	CSX_SHIFTER_OP_ASR,
	CSX_SHIFTER_OP_ROR,
};

/* **** */

void soc_core_arm_decode_coproc(soc_core_p core, soc_coprocessor_p acp);
void soc_core_arm_decode_ldst(soc_core_p core, soc_core_ldst_p ls);
void soc_core_arm_decode_shifter_operand(soc_core_p core, soc_core_dpi_p dpi);
const char* soc_core_arm_decode_shifter_op_string(uint8_t shopc);
