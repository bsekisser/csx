enum {
	CSX_CC_FLAGS_MODE_ADD,
	CSX_CC_FLAGS_MODE_SUB,
	CSX_CC_FLAGS_MODE_SHIFT_OUT
};

#define _setup_decode_rd(_opcode, _rd) \
	csx_reg_t _rd; \
	csx_decode_rd(_opcode, &_rd);

static void csx_decode_rd(uint32_t opcode, csx_reg_p rd)
{
	if(rd)
		*rd = _bits(opcode, 15, 12);
}

#define _setup_decode_rn_rd(_opcode, _rn, _rd) \
	csx_reg_t _rn, _rd; \
	csx_decode_rn_rd(_opcode, &_rn, &_rd);

static void csx_decode_rn_rd(uint32_t opcode, csx_reg_p rn, csx_reg_p rd)
{
	if(rn)
		*rn = _bits(opcode, 19, 16);

	if(rd)
		*rd = _bits(opcode, 15, 12);
}

static void csx_decode_ipubwl_rn_rd_offset(uint32_t opcode, uint8_t* ipubwl, csx_reg_p rd, csx_reg_p rn, uint16_t* offset)
{
	csx_decode_rn_rd(opcode, rn, rd);

	if(offset)
		*offset = _bits(opcode, 11, 0);

	if(ipubwl)
		*ipubwl = _bits(opcode, 25, 20);
}

enum {
	DPI_IMMEDIATE,
	DPI_RM,
};

typedef struct csx_dpi_t* csx_dpi_p;
typedef struct csx_dpi_t {
	uint8_t		rd;
	uint32_t	rd_v;
	uint8_t		rn;
	uint32_t	rn_v;
	uint8_t		rm;
	uint32_t	rm_v;

	uint8_t		type;

	uint32_t	imm;
	uint8_t		shift;
	uint8_t		shift_op;
	
	uint8_t		flag_mode;
	
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

static void csx_decode_shifter_operand(csx_p csx, uint32_t opcode, csx_dpi_p dpi)
{
	dpi->bit.i = (opcode >> 25) & 1;
	dpi->bit.s = (opcode >> 20) & 1;
	dpi->bit.x7 = (opcode >> 7) & 1;
	dpi->bit.x4 = (opcode >> 4) & 1;

	dpi->flag_mode = CSX_CC_FLAGS_MODE_SHIFT_OUT;
	
	if(dpi->bit.i)
	{
		dpi->type = DPI_IMMEDIATE;
		dpi->imm = _bits(opcode, 7, 0);
		dpi->shift = _bits(opcode, 11, 8) << 1;
		
		dpi->out.v = _ror(dpi->imm, dpi->shift);
		if(0 == dpi->shift)
			dpi->out.c = !!(csx->cpsr & CSX_PSR_C);
		else
			dpi->out.c = (dpi->out.v >> 31) & 1;

//		TRACE("i = %u, s = %u", dpi->bit.i, dpi->bit.s);

//		TRACE("imm = 0x%02x, shift = 0x%02x, out.v = 0x%08x, out.c = %1u",
//			dpi->imm, dpi->shift, dpi->out.v, dpi->out.c);
	}
	else
	{
		dpi->type = DPI_RM;

		dpi->rm = _bits(opcode, 3, 0);
		dpi->rm_v = csx_reg_get(csx, dpi->rm);
		
		TRACE("i = %u, s = %u, x7 = %u, x4 = %u, rm(%u) = 0x%08x, shift = %u, shift_op = %u",
			dpi->bit.i, dpi->bit.s, dpi->bit.x7, dpi->bit.x4,
			dpi->rm, dpi->rm_v, dpi->shift, dpi->shift_op);

		if(!dpi->bit.x4)
		{
			dpi->shift = _bits(opcode, 11, 7);
			dpi->shift_op = _bits(opcode, 6, 5);
		}
	}
}
