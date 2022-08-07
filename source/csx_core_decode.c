#include "csx.h"
#include "csx_core.h"
#include "csx_core_utility.h"

/* **** */

void csx_core_arm_decode_coproc(csx_core_p core, csx_coproc_data_p acp)
{
	if(0xe == mlBFEXT(IR, 27, 24))
	{
		acp->bit.x4 = BEXT(IR, 4);
		if(acp->bit.x4)
		{
			csx_core_arm_decode_rn_rd(IR, &acp->crn, &acp->rd);
			acp->bit.l = BEXT(IR, 20);
		}
		else
		{
			LOG_ACTION(core->csx->state |= CSX_STATE_HALT);
		}

		csx_core_arm_decode_rm(IR, &acp->crm);
		
		acp->opcode1 = mlBFEXT(IR, 23, 21);
		acp->cp_num = mlBFEXT(IR, 11, 8);
		acp->opcode2 = mlBFEXT(IR, 7, 5);
	}
}

void csx_core_arm_decode_ldst(csx_core_p core, csx_ldst_p ls)
{
	ls->ldstx = mlBFEXT(IR, 27, 25);

	ls->bit.p = BEXT(IR, 24);
	ls->bit.u = BEXT(IR, 23);
	ls->bit.bit22 = BEXT(IR, 22);
	ls->bit.w = BEXT(IR, 21);
	ls->bit.l = BEXT(IR, 20);

	csx_core_arm_decode_rn(IR, &ls->rn);

	ls->flags.s = 0;
	switch(ls->ldstx) /* decode size */
	{
		case	0x00:
			ls->bit.s6 = BEXT(IR, 6);
			ls->bit.h = BEXT(IR, 5);
			ls->flags.s = ls->bit.l && ls->bit.s6;
			switch(BMOV(ls->bit.l, 0, 2) | mlBFEXT(IR, 6, 5))
			{
				case 0x01:
				case 0x05:
				case 0x07:
					ls->rw_size = sizeof(uint16_t);
					break;
				case 0x02:
				case 0x03:
					ls->rw_size = sizeof(uint64_t);
					break;
				case 0x06:
					ls->rw_size = sizeof(uint8_t);
					break;
				default:
					LOG_ACTION(exit(1));
					break;

			}
			break;
		case	0x02:
		case	0x03:
			ls->rw_size = ls->bit.b22 ? sizeof(uint8_t) : sizeof(uint32_t);
			break;
		case	0x04:
			ls->rw_size = sizeof(uint32_t);
			break;
		default:
			LOG("ldstx = 0x%03x", ls->ldstx);
			LOG_ACTION(exit(1));
			break;
	}

	if(!(ls->ldstx & 0x04))
		csx_core_arm_decode_rd(IR, &ls->rd);
	
	ls->shift = 0;
	ls->shift_imm = 0;
	ls->rm = ~0;
	switch(ls->ldstx) /* decode addressing mode registers / data */
	{
		case	0x00:
			ls->rm_v = mlBFMOV(IR, 11, 8, 4) | mlBFEXT(IR, 3, 0);
			break;
		case	0x02: /* immediate indexed */
			ls->rm_v = mlBFEXT(IR, 11, 0);
			break;
		case	0x03: /* scaled register offset */
			ls->shift_imm = mlBFEXT(IR, 11, 7);
			ls->shift = mlBFEXT(IR, 6, 5);
			
			if((0 != ls->shift) || (0 != ls->shift_imm))
				LOG_ACTION(exit(1));
			
			csx_core_arm_decode_rm(IR, &ls->rm);
			break;
		case	0x04:
			ls->rm_v = mlBFEXT(IR, 15, 0);
			break;
	}
	
	if(0) LOG("ldstx = 0x%03x, rm = 0x%03x, rm_v = 0x%08x", ls->ldstx, ls->rm, ls->rm_v);
}

static void _csx_core_arm_decode_dpi(csx_core_p core, csx_dpi_p dpi)
{
	dpi->shift_op = CSX_SHIFTER_OP_ROR;

	dpi->rm = ~0;
	dpi->rm_v = mlBFEXT(IR, 7, 0);
	dpi->rs = ~0;
	dpi->rs_v = mlBFMOV(IR, 11, 8, 1);

	if(0 == dpi->rs_v)
		dpi->out.c = BEXT(CPSR, CSX_PSR_BIT_C);
	else
		dpi->out.c = BEXT(dpi->out.v, 31);
}

static void _csx_core_arm_decode_dpis(csx_core_p core, csx_dpi_p dpi)
{
	dpi->rs = ~0;
	dpi->rs_v = mlBFEXT(IR, 11, 7);
}

static void _csx_core_arm_decode_dprs(csx_core_p core, csx_dpi_p dpi)
{
	dpi->bit.x7 = BEXT(IR, 7);
	if(dpi->bit.x7)
	{
		TRACE("**** I = 0, x4 = 1, x7 = 1 ****");

		csx_core_disasm(core, IP, IR);
		LOG_ACTION(exit(1));
	}

	dpi->rs = mlBFEXT(IR, 11, 8);
	dpi->rs_v = csx_reg_get(core, dpi->rs) & _BM(7);
}

static void _csx_core_arm_shifter_operation_asr(csx_core_p core, csx_dpi_p dpi)
{
	uint8_t asr_v = dpi->rs_v;

	if(!dpi->bit.x4 && !dpi->rs_v)
		asr_v = 32;

	dpi->out.v = ((signed)dpi->rm_v >> asr_v);

	if(asr_v)
		dpi->out.c = BEXT(dpi->rm_v, asr_v - 1);
	else
		dpi->out.c = BEXT(CPSR, CSX_PSR_BIT_C);
}

static void _csx_core_arm_shifter_operation_lsl(csx_core_p core, csx_dpi_p dpi)
{
	dpi->out.v = dpi->rm_v << dpi->rs_v;
	if(dpi->rs_v)
		dpi->out.c = BEXT(dpi->rm_v, 32 - dpi->rs_v);
	else
		dpi->out.c = BEXT(CPSR, CSX_PSR_BIT_C);
}

static void _csx_core_arm_shifter_operation_lsr(csx_core_p core, csx_dpi_p dpi)
{
	uint8_t lsr_v = dpi->rs_v;

	if(!dpi->bit.x4 && !lsr_v)
		lsr_v = 32;

	dpi->out.v = dpi->rm_v >> lsr_v;

	if(lsr_v)
		dpi->out.c = BEXT(dpi->rm_v, lsr_v - 1);
	else
		dpi->out.c = BEXT(CPSR, CSX_PSR_BIT_C);
}

static void _csx_core_arm_shifter_operation_ror(csx_core_p core, csx_dpi_p dpi)
{
	if(!dpi->bit.i && !dpi->bit.x4 && (0 == dpi->rs_v))
	{
		dpi->out.v = BMOV(CPSR, CSX_PSR_BIT_C, 31) | (dpi->rm_v >> 1);
		dpi->out.c = dpi->rm_v & 1;
	}
	else
	{
		dpi->out.v = _ror(dpi->rm_v, dpi->rs_v);
		if(dpi->rs_v)
		{
			if(dpi->bit.i)
			{
				dpi->out.c = BEXT(dpi->out.v, 31);
			}
			else if(mlBFEXT(dpi->rs_v, 4, 0))
				dpi->out.c = BEXT(dpi->rm_v, dpi->rs_v - 1);
			else
			{
				dpi->out.v = dpi->rm_v;
				dpi->out.c = BEXT(dpi->rm_v, 31);
			}
		}
		else
			dpi->out.c = BEXT(CPSR, CSX_PSR_BIT_C);
	}
}

void csx_core_arm_decode_shifter_operand(csx_core_p core, csx_dpi_p dpi)
{
	dpi->bit.i = BEXT(IR, 25);
	dpi->operation = mlBFEXT(IR, 24, 21);
	dpi->bit.s = BEXT(IR, 20);
	dpi->bit.x7 = 0;
	dpi->bit.x4 = 0;

	dpi->wb = 1;

	if(dpi->bit.i)
		_csx_core_arm_decode_dpi(core, dpi);
	else
	{
		dpi->bit.x4 = BEXT(IR, 4); /* rs? */
		dpi->shift_op = mlBFEXT(IR, 6, 5);

		if(dpi->bit.x4)
			_csx_core_arm_decode_dprs(core, dpi);
		else
			_csx_core_arm_decode_dpis(core, dpi);

		csx_core_arm_decode_rm(IR, &dpi->rm);
		dpi->rm_v = csx_reg_get(core, dpi->rm);
	}

	switch(dpi->shift_op)
	{
		case	CSX_SHIFTER_OP_ASR:
			_csx_core_arm_shifter_operation_asr(core, dpi);
			break;
		case	CSX_SHIFTER_OP_LSL:
			_csx_core_arm_shifter_operation_lsl(core, dpi);
			break;
		case	CSX_SHIFTER_OP_LSR:
			_csx_core_arm_shifter_operation_lsr(core, dpi);
			break;
		case	CSX_SHIFTER_OP_ROR:
			_csx_core_arm_shifter_operation_ror(core, dpi);
			break;
		default:
			TRACE("**** i = %u, s = %u, x7 = %u, x4 = %u",
				!!dpi->bit.i, !!dpi->bit.s, !!dpi->bit.x7, !!dpi->bit.x4);

			TRACE("**** imm = 0x%02x, shift = 0x%02x",
				dpi->rm_v, dpi->rs_v);

			exit(1);
			break;
	}
}

static const char* shifter_op_string[] = {
	"LSL", "LSR", "ASR", "ROR"
};

const char* csx_core_arm_decode_shifter_op_string(const uint8_t shopc)
{
	return(shifter_op_string[shopc & 0x03]);
}
