#include "soc_core_trace_arm.h"

#include "soc_core_arm_inst.h"
#include "soc_core_psr.h"
#include "soc_core_shifter.h"
#include "soc_core_strings.h"
#include "soc_core_trace.h"

#include "csx_state.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

static const char* dpi_ops[16] = {
	"& ",  "^ ",  "- ",  "- ",
	"+ ",  "+ ",  "- ",  "- ",
	"& ",  "^ ",  "- ",  "+ ",
	"| ",  "== ", "& ~", "= -",

//		_alubox_ands,	_alubox_eors,	_alubox_subs,	_alubox_rsbs,
//		_alubox_adds,	_alubox_adcs,	_alubox_sbcs,	_alubox_rscs,
//		_alubox_tsts,	_alubox_teqs,	_alubox_cmps,	_alubox_cmns,
//		_alubox_orrs,	_alubox_movs,	_alubox_bics,	_alubox_mvns,
};

static void _dpi_s_s_r(soc_core_p core)
{
	_CORE_TRACE_("; /* 0x%08x %s0x%08x --> 0x%08x */",
		vR(N), dpi_ops[DPI_OPERATION], vR(SOP_V), vR(D));
}

static void _dpi_cmp_s_s_r(soc_core_p core)
{
	_CORE_TRACE_("; /* 0x%08x %s0x%08x ??? 0x%08x */",
		vR(N), dpi_ops[DPI_OPERATION], vR(SOP_V), vR(D));
}

static void _dpi_mov_s_s(soc_core_p core)
{
	if(!DPI_BIT(i25)) {
		if(mlBFEXT(IR, 11, 4)) {
			_CORE_TRACE_("; /* %s(0x%08x, %03u) = 0x%08x */", 
				shift_op_string[1][DPI_SHIFT_OP],
					vR(M), vR(S), vR(D));
		}
		else if(rR(D) == rR(M))
		{
			_CORE_TRACE_("; /* nop */");
		}
	} else {
		if(vR(S)) {
			_CORE_TRACE_("; /* ROR(0x%08x, %03u) = 0x%08x */", 
				vR(M), vR(S), vR(D));
		} else {
			_CORE_TRACE_("; /* 0x%08x */", vR(D));
		}
	}
}

void soc_core_trace_inst_dpi(soc_core_p core)
{
	if(!core->trace)
		return;

	CORE_TRACE_START();

	_CORE_TRACE_("%s%s(",
			arm_dpi_op_string[DPI_OPERATION], DPI_BIT(s20) ? "s" : "");

	if(DPI_WB)
		_CORE_TRACE_("%s", rR_NAME(D));

	if((rR(N) & 0x0f) == rR(N))
		_CORE_TRACE_("%s%s", DPI_WB ? ", " : "", rR_NAME(N));

	if(DPI_BIT(i25))
	{
		if(vR(S)) {
			_CORE_TRACE_(", ROR(%u, %u)", vR(M), vR(S));
		} else
			_CORE_TRACE_(", %u", vR(M));
	}
	else
	{
		const char* sos = shift_op_string[1][DPI_SHIFT_OP];
		
		if(DPI_BIT(x4))
			_CORE_TRACE_(", %s(%s, %s)", sos, rR_NAME(M), rR_NAME(S));
		else {
			switch(DPI_SHIFT_OP) {
				case SOC_CORE_SHIFTER_OP_ROR:
					if(!vR(S))
						_CORE_TRACE_(", RRX(%s)", sos, rR_NAME(M));
					break;
				default:
					if(!mlBFEXT(IR, 11, 4))
						_CORE_TRACE_(", %s", rR_NAME(M));
					else
						_CORE_TRACE_(", %s(%s, %u)", sos, rR_NAME(M), vR(S));
					break;
			}
		}
	}

	_CORE_TRACE_(")");

	switch(DPI_OPERATION) {
		default:
			_dpi_s_s_r(core);
			break;
		case ARM_DPI_OPERATION_BIC:
			_CORE_TRACE_("; /* 0x%08x & ~0x%08x(0x%08x) --> 0x%08x */",
				vR(N), vR(SOP_V), ~vR(SOP_V), vR(D));
			break;
		case ARM_DPI_OPERATION_CMP:
		case ARM_DPI_OPERATION_CMN:
		case ARM_DPI_OPERATION_TEQ:
		case ARM_DPI_OPERATION_TST:
			_dpi_cmp_s_s_r(core);
			break;
		case ARM_DPI_OPERATION_MOV:
			_dpi_mov_s_s(core);
			break;
		case ARM_DPI_OPERATION_MVN:
			_CORE_TRACE_("; /* 0x%08x */", vR(D));
			break;
		case ARM_DPI_OPERATION_RSB:
		case ARM_DPI_OPERATION_RSC:
			_CORE_TRACE_("; /* 0x%08x - 0x%08x --> 0x%08x */",
				vR(SOP_V), vR(N), vR(D));
			break;
	}

	CORE_TRACE_END();
}

void soc_core_trace_inst_ldst(soc_core_p core, soc_core_ldst_p ls)
{
	CORE_TRACE_START();

	/* ldr|str{cond}{b}{t} <rd>, <addressing_mode> */
	/* ldr|str{cond}{h|sh|sb|d} <rd>, <addressing_mode> */

	_CORE_TRACE_("%sr", LDST_BIT(l20) ? "ld" : "st");

	if(LDSTX & 1)
	{
		const int bit_t = !LDST_BIT(p24) && LDST_BIT(w21);

		_CORE_TRACE_("%s%s", LDST_BIT(b22) ? "b" : "", bit_t ? "t" : "");
	}
	else
	{
		const char* rws = "";
		switch(ls->rw_size)
		{
			case sizeof(uint8_t):
				rws = "b";
				break;
			case sizeof(uint16_t):
				rws = "h";
				break;
			case sizeof(uint32_t):
				break;
			case sizeof(uint64_t):
				rws = "d";
				break;
			default:
				LOG_ACTION(core->csx->state = CSX_STATE_HALT);
				break;
		}

		_CORE_TRACE_("%s%s", LDST_FLAG_S ? "s" : "", rws);
	}

	_CORE_TRACE_("(%s, %s", rR_NAME(D), rR_NAME(N));

	if((rR(M) & 0x0f) == rR(M))
		_CORE_TRACE_("[%s]", rR_NAME(M));
	else if(vR(M))
		_CORE_TRACE_("[0x%04x]%s", vR(M), LDST_BIT(w21) ? "!" : "");
	else
		_CORE_TRACE_("[0]");

	_CORE_TRACE_(") /* 0x%08x: 0x%08x */", ls->ea, vR(D));

	CORE_TRACE_END();
}
