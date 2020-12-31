#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include <capstone/capstone.h>

#include "../../include/err_test.h"

#define LOCAL_RGNDIR "../../garmin/rgn_files/"
#include "../../garmin/rgn_files/038201000610.h"

typedef struct cs_data_t* cs_data_p;
typedef struct cs_data_t {
	csh			handle;
	cs_insn*	insn;
	int			count;
	uint32_t	*opcode;
	uint8_t		*data;
}cs_data_t;

typedef struct csx_t* csx_p;
typedef struct csx_t {
	uint8_t*	data;
	uint32_t	data_size;

	uint32_t	address;
	uint32_t	next_address;

	cs_data_t	cs_data;
}csx_t;

enum {
	CSX_CODE_BIT = 8,
	CSX_DATA_BIT,
};

#define CSX_(_x) (1 << CSX_ ## _x ## _BIT)

int is_token(const char* s1, char* s2)
{
	int len = strlen(s1);
	
	return(0 == strncmp(s1, s2, len + 1));
}

void csx_mark(csx_p csx, uint32_t address, uint32_t value)
{
	(void)csx;
	(void)address;
	(void)value;
}

static int csx_normalize_reg(int reg)
{
	switch(reg)
	{
		case ARM_REG_SP:	/* 13 */
			reg = 13;
			break;
		case ARM_REG_LR:	/* 14 */
			reg = 14;
			break;
		case ARM_REG_PC:	/* 15 */
			reg = 15;
			break;
		default:
			reg -= ARM_REG_R0;
	}
	
	return(reg);
}

void csx_disasm_debug(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;
	
	uint32_t address = csx->address;
	cs_insn *insn = csd->insn;
	int count = csd->count;
	
	cs_arm* detail = &insn->detail->arm;
	
	uint8_t op_count = detail->op_count;
	
	if(!op_count)
		LOG("expected op_count > 0");
	else
		LOG("detail.op_count = 0x%02x", op_count);

	for(int i = 0; i < op_count; i++)
	{
		cs_arm_op* op = &detail->operands[i];
		
		const char *ts = "";
		
		switch(op->type)
		{
			case ARM_OP_IMM:
				ts = "ARM_OP_IMM";
				break;
			case ARM_OP_MEM:
				ts = "ARM_OP_MEM";
				break;
			case ARM_OP_REG:
				ts = "ARM_OP_REG";
				break;
		}

		LOG("op[%02u].type = 0x%02x (%s)", i, op->type, ts);
		if(op->shift.type)
		{
			LOG("op[%02u].shift.type = 0x%02x", i, op->shift.type);
			LOG("op[%02u].shift.value = 0x%04x", i, op->shift.value);
		}

		switch(op->type)
		{
			case ARM_OP_IMM:
				LOG("op[%02u].imm = 0x%08x", i, op->imm);
				break;
			case ARM_OP_MEM:
				LOG("op[%02u].base = %02u", i, op->mem.base);
				if(op->mem.index)
					LOG("op[%02u].index = %02u", i, op->mem.index);
				if(op->mem.scale)
					LOG("op[%02u].scale = %02u", i, op->mem.scale);
				if(op->mem.disp)
					LOG("op[%02u].disp = 0x%04x", i, op->mem.disp);
				if(op->mem.lshift)
					LOG("op[%02u].lshift = 0x%02u", i, op->mem.lshift);
				break;
			case ARM_OP_REG:
				LOG("op[%02u].reg = %02u", i, op->reg);
				break;
		}
	}

	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			uint64_t insn_address = insn[j].address;
			printf("0x%08llx:\t", insn_address);
			for(int k = 0; k < 4; k++)
				printf(" 0x%02x", csd->data[(j << 2) + k]);
			printf("\t\t%s\t\t%s\n", insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else {
		printf("0x%08x:\t", address);
		printf("ERROR: Failed to disassemble given code!\n");
	}
}

int csx_parse_b(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;
	cs_insn* insn = csd->insn;
	cs_arm* detail = &insn->detail->arm;

	if(1 != detail->op_count)
		return(0);

	cs_arm_op* op1 = &detail->operands[0];

	if(op1->type != ARM_OP_IMM)
		return(0);

	const char* ccs;
	switch(detail->cc)
	{
		case ARM_CC_AL:
			ccs = "b";
			break;
		case ARM_CC_NE:
			ccs = "bne";
			break;
		default:
			LOG("unhandled cc 0x%02x", detail->cc);
			break;
	}
	
	uint32_t br_address = op1->imm;

	csx_mark(csx, br_address, CSX_(CODE));
	printf("I(0x%08x, %s(0x%08x))\n", csx->address, ccs, br_address);
	csx->next_address = br_address;

	return(1);
}

int csx_parse_bic(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;

	uint8_t rd = 0;
	uint8_t rs = 0;
	uint8_t bit = 0;

	if(3 == sscanf(csd->insn[0].op_str, "r%hhu, r%hhu, #%hhx]", &rd, &rs, &bit))
	{
		printf("I(0x%08x, BIC(r[%02hhu], r[%02hhu], 0x%02x))\n",
			csx->address, rd, rs, bit);
		return(1);
	}
	return(0);
}

/*
 * 
 * ARM_INS_B,	ARM_OP_IMM, _bxx_i
 * ARM_INS_BIC,	ARM_OP_REG, ARM_OP_REG, ARM_OP_IMM, _bic_r_r_i
 * ARM_INS_LDR, ARM_OP_REG, ARM_OP_MEM, _ldr_r_m
 * ARM_INS_MOV, ARM_OP_REG, ARM_OP_REG
 * ARM_INS_STR, ARM_OP_REG, ARM_OP_MEM, _str_r_m
 *
 */

int csx_parse_ldr(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;
	cs_insn* insn = csd->insn;
	cs_arm* detail = &insn->detail->arm;

	if(2 != detail->op_count)
		return(0);

	cs_arm_op* op1 = &detail->operands[0];

	if(op1->type != ARM_OP_REG)
		return(0);

	int rd = csx_normalize_reg(op1->reg);
	
	cs_arm_op* op2 = &detail->operands[1];
	
	if(op2->type != ARM_OP_MEM)
		return(0);

	int rs = csx_normalize_reg(op2->reg);
	
	uint16_t offset = op2->mem.disp;
	if(15 == rs)
	{
		uint32_t rel_address = csx->address + 4 + offset;
		csx_mark(csx, rel_address, CSX_(DATA) | 32);
		printf("I(0x%08x, r[%02u] = LDR(%02u, 0x%04x)) \\* 0x%08x *\\\n",
			csx->address, rd, rs, offset, rel_address);
	}
	else
	{
		printf("I(0x%08x, r[%2u] = LDR(r[%2u], 0))\n",
			csx->address, rd, rs);
	}
	
	return(1);
}

int csx_parse_mov(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;

	uint8_t rd = 0;
	uint8_t rs = 0;

	if(2 == sscanf(csd->insn[0].op_str, "r%hhu, r%hhu", &rd, &rs))
	{
		printf("I(0x%08x, r[%02hhu] = r[%02hhu])\n",
			csx->address, rd, rs);
		return(1);
	}
	return(0);
}

int csx_parse_orr(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;

	uint8_t rd = 0;
	uint8_t rs = 0;
	uint8_t bit = 0;

	if(3 == sscanf(csd->insn[0].op_str, "r%hhu, r%hhu, #%hhx", &rd, &rs, &bit))
	{
		printf("I(0x%08x, ORR(r[%02hhu], r[%02hhu], 0x%02x))\n",
			csx->address, rd, rs, bit);
		return(1);
	}
	return(0);
}

int csx_parse_str(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;

	uint8_t rd = 0;
	uint8_t rs = 0;
//	uint8_t offset = 0;

	if(2 == sscanf(csd->insn[0].op_str, "r%hhu, [r%hhu]", &rd, &rs))
	{
		printf("I(0x%08x, STR(r[%02hhu], r[%02hhu]))\n",
			csx->address, rd, rs);
		return(1);
	}
	return(0);
}

typedef int (*parse_fn_t)(csx_p csx);

typedef struct token_t* token_p;
typedef struct token_t {
	unsigned int	match;
	arm_op_type		type[36];
	parse_fn_t		fn;
}token_t;

static arm_op_type _csx_ins_b_types[] = {
	ARM_OP_IMM };

typedef struct csx_ins_t {
	unsigned int	op;
	parse_fn_t		fn;
	arm_op_type		*types;
}csx_ins_t;

csx_ins_t _csx_ins_b = {
	ARM_INS_B,	csx_parse_b, _csx_ins_b_types,
	0, 0, 0 };

csx_ins_t _csx_ins_ldr = {
	ARM_INS_LDR, csx_ins_ldr, _cxs_ins_ldr_types,
	0, 0, 0 };

token_t token_list[] = {
	{	ARM_INS_B, csx_parse_b	},
//	{	ARM_INS_BIC,	csx_parse_bic	},
//	{	ARM_INS_LDR,	csx_parse_ldr	},
	{	ARM_INS_LDR,
			.type = {	ARM_OP_REG, ARM_OP_MEM },
					csx_parse_ldr },

//	{	ARM_INS_MOV,	csx_parse_mov	},
//	{	ARM_INS_ORR,	csx_parse_orr	},
//	{	ARM_INS_STR,	csx_parse_str	},
	{ 0, 0 }
};

void csx_parse(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;
	cs_insn* insn = csd->insn;

	for(int i = 0;; i++)
	{
		token_p token = &token_list[i];
		
		if(0 == token->match)
			break;
		
		if(insn->id == token->match)
		{
			if(token->fn(csx))
				return;
			else
				break;
		}
	}

	csx_disasm_debug(csx);
}

void csx_disasm(csx_p csx)
{
	uint32_t address = csx->address;
	csx->next_address = address + 4;
	
	cs_data_p csd = &csx->cs_data;

	csd->data = &csx->data[address];
	
	cs_insn* insn;

	csd->count = cs_disasm(csd->handle, csd->data, 4, address, 0, &insn);
	csd->insn = insn;
	
	if (csd->count > 0)
	{
		csx_parse(csx);
	}
	else
		csx_mark(csx, address, CSX_(DATA) | 32);
	
	csx->address = csx->next_address;
}

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
	cs_assert_success(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON));

	csx->cs_data.handle = handle;
	csx->address = 0;

	for(int i = 0; i < 256; i++)
		csx_disasm(csx);

	cs_close(&handle);

	return(0);
}
