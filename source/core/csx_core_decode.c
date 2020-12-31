#include "csx.h"
#include "csx_core.h"

/* **** */

void csx_core_arm_decode_coproc(csx_core_p core, uint32_t opcode, csx_coproc_data_p acp)
{
	if(0xe == _bits(opcode, 27, 24))
	{
		acp->bit.x4 = BIT_OF(opcode, 4);
		if(acp->bit.x4)
		{
			csx_core_arm_decode_rn_rd(opcode, &acp->crn, &acp->rd);
			acp->bit.l = BIT_OF(opcode, 20);
		}
		else
		{
			LOG_ACTION(core->csx->state |= CSX_STATE_HALT);
		}
			
		csx_core_arm_decode_rm(opcode, &acp->crm);
		
		acp->opcode1 = _bits(opcode, 23, 21);
		acp->cp_num = _bits(opcode, 11, 8);
		acp->opcode2 = _bits(opcode, 7, 5);
	}
}

void csx_core_arm_decode_ldst(csx_core_p core, uint32_t opcode, csx_ldst_p ls)
{
	csx_core_arm_decode_rn_rd(opcode, &ls->rn, &ls->rd);
	
	ls->bit.i2x_76 = _bits(opcode, 27, 26);
	ls->bit.i25 = BIT_OF(opcode, 25);
	
	ls->bit.l = BIT_OF(opcode, 20);

	switch(ls->bit.i2x_76)
	{
		case 0x01:
			ls->bit.b = BIT_OF(opcode, 22);

			ls->rw_size = ls->bit.b ? sizeof(uint8_t) : sizeof(uint32_t);

			if(ls->bit.i25)
			{
				LOG_ACTION(core->csx->state = CSX_STATE_HALT);
				ls->shift_imm = _bits(opcode, 11, 7);
				ls->shift = _bits(opcode, 6, 5);
				ls->rm = _bits(opcode, 3, 0);
			}
			else
			{
				ls->rm = -1;
				ls->rm_v = _bits(opcode, 11, 0);
			}
			break;
		case 0x00:
			ls->bit.i22 = BIT_OF(opcode, 22);
			if(ls->bit.i22)
			{
				ls->rm = -1;
				ls->rm_v = (_bits(opcode, 11, 8) << 4) | _bits(opcode, 3, 0);
			}
			else
				csx_core_arm_decode_rm(opcode, &ls->rm);

			ls->bit.s = BIT_OF(opcode, 6);
			ls->bit.h = BIT_OF(opcode, 5);
			
			ls->flags.s = ls->bit.l && ls->bit.s;
			
			switch(((!!ls->bit.l) << 2) | ((!!ls->bit.s) << 1) | !!ls->bit.h)
			{
				case	0x01:
				case	0x05:
				case	0x07:
					ls->rw_size = sizeof(uint16_t);
					break;
				case	0x02:
				case	0x03:
					ls->rw_size = sizeof(uint64_t);
					break;
				case	0x06:
					ls->rw_size = sizeof(uint8_t);
					break;
				default:
					LOG_ACTION(core->csx->state = CSX_STATE_HALT);
					break;
			}
			break;
	}

	ls->bit.p = BIT_OF(opcode, 24);
	ls->bit.u = BIT_OF(opcode, 23);
	/* i22, b */
	ls->bit.w = BIT_OF(opcode, 21);
	
	if(0)
	{
		uint8_t ipubwl = _bits(opcode, 25, 20);
		char* t, ts[8];
		
		if(0x01 == ls->bit.i2x_76)
		{
			t = "ipubwl";
		}
		else
		{
			t = " puiwl";
		}

		for(int i = 0; i < 6; i++)
		{
			if((ipubwl >> (5 - i)) & 1)
				ts[i] = toupper(t[i]);
			else
				ts[i] = t[i];
		}
		
		ts[6] = 0;
		
		TRACE("(0x%08x) (0x%02x) (0x%02x) %s", opcode, ls->bit.i2x_76, ipubwl, ts);
	}
}

void csx_core_arm_decode_shifter_operand(csx_core_p core, uint32_t opcode, csx_dpi_p dpi)
{
	dpi->bit.i = (opcode >> 25) & 1;
	dpi->bit.s = (opcode >> 20) & 1;
	dpi->bit.x7 = 0;
	dpi->bit.x4 = 0;

	dpi->wb = 1;
	dpi->flag_mode = CSX_CC_FLAGS_MODE_SHIFT_OUT;

	if(dpi->bit.i)
	{
		dpi->shift_op = CSX_SHIFTER_OP_ROR;

		dpi->rm = -1;
		dpi->rm_v = _bits(opcode, 7, 0);
		dpi->rs = -1;
		dpi->rs_v = _bits(opcode, 11, 8) << 1;

		if(0 == dpi->rs_v)
			dpi->out.c = !!(CPSR & CSX_PSR_C);
		else
			dpi->out.c = (dpi->out.v >> 31) & 1;
	}
	else
	{
		dpi->bit.x4 = (opcode >> 4) & 1; /* rs? */
		dpi->shift_op = _bits(opcode, 6, 5);

		if(dpi->bit.x4)
		{
			dpi->bit.x7 = (opcode >> 7) & 1;
			if(dpi->bit.x7)
			{
				TRACE("**** I = 0, x4 = 1, x7 = 1 ****");
				LOG_ACTION(core->csx->state = CSX_STATE_HALT);
			}

			dpi->rs = _bits(opcode, 11, 8);
			dpi->rs_v = _bits(csx_reg_get(core, dpi->rs), 7, 0);
		}
		else
		{
			dpi->rs = -1;
			dpi->rs_v = _bits(opcode, 11, 7);
		}

		csx_core_arm_decode_rm(opcode, &dpi->rm);
		dpi->rm_v = csx_reg_get(core, dpi->rm);
	}

	switch(dpi->shift_op)
	{
		case	CSX_SHIFTER_OP_ASR:
		{
			uint8_t asr_v = dpi->rs_v;

			if(!dpi->bit.x4)
				asr_v = asr_v ? asr_v : 32;

			dpi->out.v = ((signed)dpi->rm_v >> asr_v);

			if(asr_v)
				dpi->out.c = (dpi->rm_v >> (asr_v - 1)) & 1;
			else
				dpi->out.c = CPSR & CSX_PSR_C;
		}break;
		case	CSX_SHIFTER_OP_LSL:
			dpi->out.v = dpi->rm_v << dpi->rs_v;
			if(dpi->rs_v)
				dpi->out.c = (dpi->rm_v >> (32 - dpi->rs_v)) & 1;
			else
				dpi->out.c = CPSR & CSX_PSR_C;
			break;
		case	CSX_SHIFTER_OP_LSR:
		{
			uint8_t lsr_v = dpi->rs_v;

			if(!dpi->bit.x4)
				lsr_v = lsr_v ? lsr_v : 32;

			dpi->out.v = dpi->rm_v >> lsr_v;

			if(lsr_v)
				dpi->out.c = (dpi->rm_v >> (lsr_v - 1)) & 1;
			else
				dpi->out.c = !!(CPSR & CSX_PSR_C);
		}break;
		case	CSX_SHIFTER_OP_ROR:
			if(!dpi->bit.i && !dpi->bit.x4 && (0 == dpi->rs_v))
			{
				dpi->out.v = ((CPSR & CSX_PSR_C) ? (1 << 31) : 0);
				dpi->out.v |= dpi->rm_v >> 1;
				dpi->out.c = dpi->rm_v & 1;
			}
			else
			{
				dpi->out.v = _ror(dpi->rm_v, dpi->rs_v);
				if(dpi->rs_v)
				{
					if(dpi->bit.i)
					{
						dpi->out.c = (dpi->out.v >> 31) & 1;
					}
					else if(_bits(dpi->rs_v, 4, 0))
						dpi->out.c = (dpi->rm_v >> (dpi->rs_v - 1)) & 1;
					else
					{
						dpi->out.v = dpi->rm_v;
						dpi->out.c = (dpi->rm_v >> 31) & 1;
					}
				}
				else
					dpi->out.c = !!(CPSR & CSX_PSR_C);
			}
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

const char* csx_core_arm_decode_shifter_op_string(uint8_t shopc)
{
	return(shifter_op_string[shopc & 0x03]);
}
