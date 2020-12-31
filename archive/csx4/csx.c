#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <capstone/capstone.h>

#include "../../include/err_test.h"
#include "../../include/data.h"

#define LOCAL_RGNDIR "../garmin/rgn_files/"
#include "../../garmin/rgn_files/038201000610.h"

#define TRACE(_f, args...) \
	do { \
		uint32_t pc = csx_reg_get(csx, INSN_PC); \
		printf("0x%08x: " _f "\n", pc, ## args); \
	}while(0);

#define INSN_PC (-(rPC))

#define rPC 15


typedef struct csx_t* csx_p;
typedef struct csx_t {
	uint32_t 	regs[16];
	
	uint32_t	insn_pc;
	
	void*		data;
	uint32_t	data_size;

	csh			cs_handle;
}csx_t;

/* **** */

static uint32_t csx_reg_get(csx_p csx, uint32_t r)
{
	if(INSN_PC == r)
		return(csx->insn_pc);

	return(csx->regs[r]);
}

static void csx_reg_set(csx_p csx, uint32_t r, uint32_t v)
{
	if(INSN_PC == r)
		csx->insn_pc = v;
	else
		csx->regs[r] = v;
}

/* **** */

uint32_t csx_mmio_read(csx_p csx, uint32_t ea, uint8_t size)
{
	uint32_t res = 0;

	return(res);
}

void csx_mmio_write(csx_p csx, uint32_t ea, uint32_t v, uint8_t size)
{
}

/* **** */

uint32_t csx_mmu_read(csx_p csx, uint32_t ea, uint8_t size)
{
	uint32_t res = 0;

	if(ea <= csx->data_size)
		res = ((uint32_t*)csx->data)[ea];
	else if(ea >= 0xfffc0000)
		res = csx_mmio_read(csx, ea, size);

	return(res);
}

void csx_mmu_write(csx_p csx, uint32_t ea, uint32_t v, uint8_t size)
{
	if(ea >= 0xfffc0000)
		csx_mmio_write(csx, ea, v, size);
}

/* **** */

#define ALU_r_r_v(_name, _op) \
	static void _name(csx_p, uint8_t rd, uint8_t rs, uint8_t v) \
	{ \
		uint32_t rsv = csx_reg_get(csx, rs); \
		uint32_t res = rsv + v; \
		csx_reg_set(csx, rd, res); \
	}

#define CSX_INST_CC_MASK (~((1 << 28) - 1))

#define CSX_INST_Rn_MASK ((~((1 << 5) - 1)) << 16)
#define CSX_INST_Rd_MASK ((~((1 << 5) - 1)) << 12)
#define CSX_INST_RnRd_MASK (CSX_INST_Rn_MASK | CSX_INST_Rd_MASK)

#define CSX_INST_B_OFFSET_MASK ((1 << 24) - 1)
#define CSX_INST_BL_BIT (1 << 24)

#define CSX_INST_LDST_OFFSET_MASK ((1 << 12) - 1)

#define CSX_INST_L_BIT (1 << 20)
#define CSX_INST_W_BIT (1 << 21)
#define CSX_INST_B_BIT (1 << 22)
#define CSX_INST_U_BIT (1 << 23)
#define CSX_INST_P_BIT (1 << 24)

#define CSX_INST_LDST_LWBUP_BITS \
	(CSX_INST_L_BIT \
		| CSX_INST_W_BIT \
		| CSX_INST_B_BIT \
		| CSX_INST_U_BIT \
		| CSX_INST_P_BIT)

#define CSX_INST_LDST_MASK \
	~(CSX_INST_CC_MASK \
		| CSX_INST_RnRd_MASK \
		| CSX_INST_LDST_LWBUP_BITS \
		| CSX_INST_LDST_OFFSET_MASK)

#define CSX_INST_B (5 << 25)
#define CSX_INST_B_MASK (~(CSX_INST_CC_MASK | CSX_INST_B_OFFSET_MASK | CSX_INST_BL_BIT))

void csx_decode_ipubwl_rd_rn_offset(uint32_t opcode, uint8_t* ipubwl, uint8_t* rd, uint8_t* rn, uint16_t* offset)
{
	uint16_t offset_v = _bits(opcode, 11, 0);
	uint8_t rn_v = _bits(opcode, 19, 16);
	uint8_t	rd_v = _bits(opcode, 15, 12);
	uint8_t ipubwl_v = _bits(opcode, 25, 20);
	
	uint32_t bit_l = opcode & (1UL << 20);

	if(offset)
		*offset = offset_v;
	if(rn)
		*rn = rn_v;
	if(rd)
		*rd = rd_v;
	if(ipubwl)
		*ipubwl = ipubwl_v;

	if(!offset || !rn || !rd || !ipubwl)
	{
		char t[] = "ipubwl";

		for(int i = 0; i < 7; i++)
		{
			if((ipubwl_v >> (5 - i)) & 1)
				t[i] = toupper(t[i]);
		}

		LOG("%s -- 0x%02x, rd[0x%02x] = rn[0x%02x][0x%04x]", t, ipubwl_v, rd_v, rn_v, offset_v);
		
		LOG("\n\n");
		
		LOG("bit_l = 0x%08x", bit_l);
	}
}

void csx_decode_rd_rn_shifter_operand(uint32_t opcode, uint8_t* rd, uint8_t* rn, uint16_t* shifter_operand)
{
	uint8_t ipubwl;
	
	return(csx_decode_ipubwl_rd_rn_offset(opcode, &ipubwl, rd, rn, shifter_operand));
}


static uint32_t _bit_field(uint8_t h, uint8_t l)
{
	uint32_t hbf = (1UL << (h + 1)) - 1;
	uint32_t lbf = (1UL << l) - 1;
	
	uint32_t res = hbf - lbf;
	
	LOG("hbf = 0x%08x, lbf = 0x%08x, res = 0x%08x", hbf, lbf, res);
	
	return(res);
}

uint8_t csx_decode(uint32_t opcode)
{
	uint32_t check = opcode & _bit_field(27, 25);
	switch(check)
	{
		case 0x04000000:
			return(ARM_INS_LDR);
			break;
		case 0x0a000000:
			return(ARM_INS_B);
			break;
	}

	LOG("check = 0x%04x:0x%04x", ((check >> 16) & 0xffff), check & 0xffff);
	
	uint32_t dpis_opcode = opcode & _bit_field(24, 21);
	check |= dpis_opcode;

	switch(check)
	{
		case 0x01a00000:
			return(ARM_INS_MOV);
			break;
	}

	LOG("check = 0x%04x:0x%04x", ((check >> 16) & 0xffff), check & 0xffff);
	LOG("dpis = 0x%08x", dpis_opcode >> 21);

	return(0);
}

static int csx_inst_b(csx_p csx, uint32_t opcode)
{
//	int l_bit = !!(opcode & CSX_INST_BL_BIT);
	uint32_t offset = (opcode & CSX_INST_B_OFFSET_MASK);
	
//	uint32_t pc = csx_reg_get(csx, rPC);
	uint32_t new_pc = csx->new_pc + 4 + (offset << 2);
	
	TRACE("b(0x%08x)", new_pc);
	
	csx->new_pc = new_pc;
	
	return(0);
}

static int csx_inst_ldst(csx_p csx, uint32_t opcode)
{
	uint16_t offset;
	uint8_t rn, rd, ipubwl;

	csx_decode_ipubwl_rd_rn_offset(opcode, &ipubwl, &rd, &rn, &offset);

	if(ipubwl & 1) {
		uint32_t rn_v = csx_reg_get(csx, rn);
		uint32_t ea = rn_v + offset;
		uint32_t res = csx_mmu_read(csx, ea, sizeof(uint32_t));

		if(offset)
		{
			TRACE("r[%u] = r[%u][0x%04x] /* 0x%08x */", rd, rn, offset, ea);
		}
		else
		{
			TRACE("r[%u] = r[%u]", rd, rn);
		}

		csx_reg_set(csx, rd, res);
	}
	
	return(1);
}

static int csx_inst_mov(csx_p csx, uint32_t opcode)
{
		if(opcode & (1 << 4))
			return(1);

		uint8_t rd, rn;
		uint16_t shifter_operand;

		csx_decode_rd_rn_shifter_operand(opcode, &rd, &rn, &shifter_operand);
		
		uint8_t shift_imm = _bits(shifter_operand, 11, 7);
		uint8_t shift = _bits(shifter_operand, 6, 5);
		uint8_t rm = _bits(shifter_operand, 3, 0);
		
		uint32_t rn_v = csx_reg_get(csx, rn);
		uint32_t res = rn_v;
		
		const char* ss = "";
		
		switch(shift)
		{
			case 0x00:
				res <<= shift_imm;
				ss = "<<";
				break;
			case 0x01:
				res >>= shift_imm;
				ss = ">>";
			default:
				return(1);
		}

		TRACE("r[%u](0x%08x) = r[%u](0x%08x) %s 0x%04x", rd, res, rn, rn_v, ss, shift_imm);

		csx_reg_set(csx, rd, rn_v);
		return(1);
}


/* **** */

void csx_disasm_debug(csx_p csx, uint32_t address, uint32_t opcode)
{
//	csh handle = csx->cs_handle;

	uint8_t* opcode_data = (uint8_t*)&opcode;

	cs_insn* insn;
	int count = cs_disasm(csx->cs_handle, opcode_data, 4, address, 0, &insn);

	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			uint64_t insn_address = insn[j].address;
			printf("/* 0x%08llx:\t", insn_address);
			for(int k = 0; k < 4; k++)
				printf(" 0x%02x", (opcode_data[k]) & 0xff);
			printf("\t\t%s\t\t%s */\n", insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else {
		printf("0x%08x:\t", address);
		printf("ERROR: Failed to disassemble given code!\n");
	}
}

static int csx_step(csx_p csx)
{
	int res = 0;
	uint32_t pc = csx_reg_get(csx, rPC);
	
	csx_reg_set(csx, INSN_PC, pc);
	csx_reg_set(csx, rPC, pc + 4);
	
	uint32_t opcode = csx_mmu_read(csx, pc, sizeof(uint32_t));
	
//	uint8_t op_cc = opcode >> (32 - 4) & 0x0f;
	
	switch(csx_decode(opcode))
	{
		case ARM_INS_B:
			res = csx_inst_b(csx, opcode);
			break;
		case ARM_INS_LDR:
			res = csx_inst_ldst(csx, opcode);
			break;
		case ARM_INS_MOV:
			res = csx_inst_mov(csx, opcode);
			break;
		default:
		{
			csx_disasm_debug(csx, pc, opcode);
			return(1);
		}
	}

	if(res)
		csx_disasm_debug(csx, pc, opcode);
	
	return(0);
}

/* **** */

int main(void)
{
	csx_t ccsx, *csx = &ccsx;
	
	int fd;

	LOG("opening " LOCAL_RGNDIR RGNFileName "_loader.bin...");

	ERR(fd = open(LOCAL_RGNDIR RGNFileName "_loader.bin", O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));
	
	void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);
	
	csx->data = data;
	csx->data_size = sb.st_size;
	
	close(fd);

	csh handle;
	cs_assert_success(cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle));
//	cs_assert_success(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON));

	csx->cs_handle = handle;

	csx_reg_set(csx, rPC, 0);
	
	while(!csx_step(csx))
		;

	cs_close(&handle);

	return(0);
}
