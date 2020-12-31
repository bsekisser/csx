#include "csx.h"
#include "csx_core.h"

#include <capstone/capstone.h>

void csx_core_disasm(csx_core_p core, uint32_t address, uint32_t opcode)
{
	csh handle;
	cs_insn *insn;

	int b0 = BIT_OF(address, 0);
	int size = b0 ? sizeof(uint16_t) : sizeof(uint32_t);
	int mode = b0 ? CS_MODE_THUMB : CS_MODE_ARM;

	cs_assert_success(cs_open(CS_ARCH_ARM, mode, &handle));
	
	uint8_t *insn_data = (uint8_t*)&opcode;

	int count = cs_disasm(handle, insn_data, size, address, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			uint64_t insn_address = insn[j].address;
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
}
