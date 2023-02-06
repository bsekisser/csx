#include "../../include/bitfield.h"
#include "../../include/log.h"

void main(void)
{
//	[0x0000 ... (0x1000 | mlBF(10, 0))] = soc_core_thumb_sbi_imm5_rm_rd,
	LOG("0x%04x ... 0x%04x", 0x0000, (0x1000 | mlBF(10, 0)));

//	[0x1800 ... (0x1800 | mlBF(9, 0))] = soc_core_thumb_add_sub_rn_rd,
	LOG("0x%04x ... 0x%04x", 0x1800, (0x1800 | mlBF(9, 0)));

//	[0x1c00 ... (0x1c00 | mlBF(9, 0))] = soc_core_thumb_add_sub_rn_rd,
	LOG("0x%04x ... 0x%04x", 0x1c00, (0x1c00 | mlBF(9, 0)));

//	[0x2000 ... (0x2000 | mlBF(12, 0))] = soc_core_thumb_ascm_rd_i,
	LOG("0x%04x ... 0x%04x", 0x2000, (0x2000 | mlBF(12, 0)));

//	[0x4000 ... (0x4000 | mlBF(9, 0))] = soc_core_thumb_dp_rms_rdn,
	LOG("0x%04x ... 0x%04x", 0x4000, (0x4000 | mlBF(9, 0)));

//	[0x4400 ... (0x4600 | mlBF(7, 0))] = soc_core_thumb_sdp_rms_rdn,
	LOG("0x%04x ... 0x%04x", 0x4400, (0x4600 | mlBF(7, 0)));

//	[0x4700 ... (0x4700 | mlBF(7, 0))] = soc_core_thumb_bx,
	LOG("0x%04x ... 0x%04x", 0x4700, (0x4700 | mlBF(7, 0)));

//	[0x4800 ... (0x4800 | mlBF(10, 0))] = soc_core_thumb_ldst_rd_i,
	LOG("0x%04x ... 0x%04x", 0x4800, (0x4800 | mlBF(10, 0)));

//	[0x5000 ... (0x5000 | mlBF(11, 0))] = soc_core_thumb_ldst_rm_rn_rd,
	LOG("0x%04x ... 0x%04x", 0x5000, (0x5000 | mlBF(11, 0)));

//	[0x6000 ... (0x6000 | mlBF(12, 0))] = soc_core_thumb_ldst_bwh_o_rn_rd,
	LOG("0x%04x ... 0x%04x", 0x6000, (0x6000 | mlBF(12, 0)));

//	[0x8000 ... (0x8000 | mlBF(11, 0))] = soc_core_thumb_ldst_bwh_o_rn_rd,
	LOG("0x%04x ... 0x%04x", 0x8000, (0x8000 | mlBF(11, 0)));

//	[0x9000 ... (0x9000 | mlBF(11, 0))] = soc_core_thumb_ldst_rd_i,
	LOG("0x%04x ... 0x%04x", 0x9000, (0x9000 | mlBF(11, 0)));

//	[0xa000 ... (0xa000 | mlBF(11, 0))] = soc_core_thumb_add_rd_pcsp_i,
	LOG("0x%04x ... 0x%04x", 0xa000, (0xa000 | mlBF(11, 0)));

//	[0xb000 ... (0xb000 | mlBF(7, 0))] = soc_core_thumb_add_sub_sp_i7,
	LOG("0x%04x ... 0x%04x", 0xb000, (0xb000 | mlBF(7, 0)));

//	[0xb100 ... 0xb1ff] = soc_core_thumb_step_undefined,
//	[0xb200 ... (0xb200 | mlBF(7, 0))] = soc_core_thumb_step_unimplimented, /* sign / zero extend */
//	[0xb300 ... 0xb3ff] = soc_core_thumb_step_undefined,
//	[0xb400 ... (0xb400 | mlBF(8, 0))] = soc_core_thumb_pop_push,
//	[0xb640 ... 0xb64f] = soc_core_thumb_step_unpredictable, /* unpredictable */
//	[0xb650 ... 0xb65f] = soc_core_thumb_step_unimplimented, /* set endianness */
//	[0xb660 ... 0xb667] = soc_core_thumb_step_unimplimented, /* change processor state */
//	[0xb668 ... 0xb66f] = soc_core_thumb_step_unpredictable, /* unpredictable */
//	[0xb670 ... 0xb677] = soc_core_thumb_step_unimplimented, /* change processor state */
//	[0xb678 ... 0xb67f] = soc_core_thumb_step_unpredictable, /* unpredictable */
//	[0xb700 ... 0xb7ff] = soc_core_thumb_step_undefined,
//	[0xb800 ... 0xb9ff] = soc_core_thumb_step_undefined,
//	[0xba00 ... (0xba40 | mlBF(5, 0))] = soc_core_thumb_step_unimplimented, /* reverse bytes */
//	[0xba80 ... (0xba80 | mlBF(5, 0))] = soc_core_thumb_step_undefined, 
//	[0xbac0 ... (0xbac0 | mlBF(5, 0))] = soc_core_thumb_step_unimplimented, /* reverse bytes */
//	[0xbb00 ... 0xbbff] = soc_core_thumb_step_undefined,
//	[0xbc00 ... (0xbc00 | mlBF(8, 0))] = soc_core_thumb_pop_push,
//	[0xbe00 ... (0xbe00 | mlBF(7, 0))] = soc_core_thumb_step_unimplimented, /* software breakpoint */
//	[0xbf00 ... 0xbfff] = soc_core_thumb_step_undefined,
//	[0xc000 ... (0xc000 | mlBF(11, 0))] = soc_core_thumb_ldstm_rn_rxx,
	LOG("0x%04x ... 0x%04x", 0xc000, (0xc000 | mlBF(11, 0)));

//	[0xd000 ... (0xddff] = soc_core_thumb_bcc,
//	[0xde00 ... (0xdeff] = soc_core_thumb_step_undefined, /* undefined instruction */
//	[0xdf00 ... (0xdfff] = soc_core_thumb_step_unimplimented, /* swi */
//	[0xe800 ... (0xe800 | mlBF(10, 0))] = soc_core_thumb_step_0xe800,
	LOG("0x%04x ... 0x%04x", 0xe800, (0xe800 | mlBF(10, 0)));

//	[0xe000 ... (0xe000 | mlBF(10, 0))] = soc_core_thumb_bxx,
	LOG("0x%04x ... 0x%04x", 0xe000, (0xe000 | mlBF(10, 0)));

//	[0xf000 ... (0xf000 | mlBF(10, 0))] = soc_core_thumb_bxx,
	LOG("0x%04x ... 0x%04x", 0xf000, (0xf000 | mlBF(10, 0)));

//	[0xf800 ... (0xf800 | mlBF(10, 0))] = soc_core_thumb_bxx,
	LOG("0x%04x ... 0x%04x", 0xf800, (0xf800 | mlBF(10, 0)));
}
