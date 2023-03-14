#include "soc_core_disasm.h"
#include "soc_core_psr.h"

/* **** */

#include "capstone_assert_test.h"
#include "log.h"

/* **** */

#include <capstone/capstone.h>

/* **** */

static void _soc_core_disasm(soc_core_p core, uint32_t address, uint32_t opcode, int thumb)
{
	csh handle = 0;
	cs_insn *insn = 0;

	const size_t size = thumb ? sizeof(uint16_t) : sizeof(uint32_t);
	const int mode = thumb ? CS_MODE_THUMB : CS_MODE_ARM;

	cs_assert_success(cs_open(CS_ARCH_ARM, mode, &handle));

	const uint8_t *insn_data = (uint8_t*)&opcode;

	size_t count = cs_disasm_iter(handle, insn_data, size, address, &insn);

	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			const uint64_t insn_address = insn[j].address;
			printf("0x%08llx:\t", insn_address);
			for(int k = 0; k < size; k++)
				printf(" 0x%02x", insn_data[(j << 2) + k]);
			printf("\t\t%s\t\t%s\n", insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("0x%08x:(0x%02x): Failed to disassemble given code!\n", address, size);

	cs_close(&handle);

	UNUSED(core);
}

void soc_core_disasm(soc_core_p core, uint32_t address, uint32_t opcode)
{
	if(BTST(CPSR, SOC_CORE_PSR_BIT_T))
		soc_core_disasm_thumb(core, address, opcode);
	else
		soc_core_disasm_arm(core, address, opcode);
}

void soc_core_disasm_arm(soc_core_p core, uint32_t address, uint32_t opcode)
{
	_soc_core_disasm(core, address & ~3, opcode, 0);
}

void soc_core_disasm_thumb(soc_core_p core, uint32_t address, uint32_t opcode)
{
	_soc_core_disasm(core, address & ~1, opcode, 1);
}
