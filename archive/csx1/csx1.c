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

#define LOCAL_RGNDIR "../garmin/rgn_files/"
#include "../../garmin/rgn_files/038201000610.h"

#define ERROR_OUT(_x) \
	do { \
		printf("\n\n%s:%s:%u -- %u (%s)\n", __FILE__, __FUNCTION__, __LINE__, errno, strerror(errno)); \
		if(_x) \
			printf("%s\n", _x); \
		return(1); \
	}while(0);
	
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

void csx_disasm_debug(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;
	cs_insn* insn = csd->insn;
	
	uint32_t address = csx->address;
	int count = csd->count;
	
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			uint64_t insn_address = insn[j].address;
			printf("/* 0x%08llx:\t", insn_address);
			for(int k = 0; k < 4; k++)
				printf(" 0x%02x", csd->data[(j << 2) + k]);
			printf("\t\t%s\t\t%s */\n", insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else {
		printf("0x%08x:\t", address);
		printf("ERROR: Failed to disassemble given code!\n");
		exit(-1);
	}
}

int strcmp_px(const char* s1, char* s2, char** dst, char* px)
{
	int len = strlen(s1);
	int ret = strncmp(s1, s2, len);
	
	if(0 == ret) {
		if(*dst)
			*dst = s2 + len;
		printf("%s", px ? px : s1);
	}
	
	return(0 == ret);
}

int csx_process_op_str(csx_p csx)
{
	cs_data_p csd = &csx->cs_data;
	cs_insn* insn = csd->insn;
//	cs_detail detail = csd->insn->detail;

	int count = 0, lbrac = 0;
	uint32_t vxx = 0;
	char c, *dst, *src;
	
	uint32_t inst_cc = (csd->opcode[0] >> (32 - 4)) & 0x0f;
	
	if(0x0f == inst_cc)
		return(1);
	
	char ccs[5];
	ccs[0] = (inst_cc & (1 << 3)) ? 'N' : 'n';
	ccs[1] = (inst_cc & (1 << 2)) ? 'Z' : 'z';
	ccs[2] = (inst_cc & (1 << 1)) ? 'C' : 'c';
	ccs[3] = (inst_cc & (1 << 0)) ? 'V' : 'v';
	ccs[4] = 0;
	
	printf("I(0x%08x,%s, ", csx->address, ccs);
		
	src = csd->insn[0].mnemonic;
	
	if(0x0e != inst_cc)
	{
		printf("/* %s */ ", src);
		switch(insn->id)
		{
			case ARM_INS_AND:
				printf("aand(");
				break;
			case ARM_INS_B:
				printf("b(");
				break;
			case ARM_INS_CMP:
				printf("cmp(");
				break;
			case ARM_INS_LDR:
				printf("ldr(");
				break;
			case ARM_INS_MOV:
				printf("mov(");
				break;
			default:
				printf(")\n\n");
				return(1);
		}
	}
	else
	{
		switch(insn->id)
		{
			case ARM_INS_AND:
				printf("aand(");
				break;
			default:
				printf("%s(", src);
				break;
		}
	}
	
	src = csd->insn[0].op_str;
	while((c = src[0]))
	{
		char c2 = src[1];
		if((' ' == c) || (',' == c))
		{
			printf("%c", c);
			src++;
		}
		else if(('#' == c) || (('0' == c) && ('x' == c2)))
		{
			if('#' == c)
				src++;
			vxx = strtol(src, &dst, 0);
			printf("%u", vxx);
			if(src != dst)
				src = dst;
			else
				ERROR_OUT(src);
		}
		else if('[' == c)
		{
			src++;
			lbrac++;
//			printf("REG(");
		}
		else if(']' == c)
		{
			src++;
			lbrac--;
//			printf("");
		}
		else if('!' == c)
		{
			src++;
			printf(" WRITE_BACK ");
		}
		else if('{' == c)
		{
			src++;
			lbrac++;
			printf(" LBRACE ");
		}
		else if('}' == c)
		{
			src++;
			lbrac--;
			printf(" RBRACE ");
		}
		else if(strcmp_px("apsr", src, &src, "APSR"))
			;
		else if(strcmp_px("cpsr_c", src, &src, "CPSR_C"))
			;
		else if(strcmp_px("fp", src, &src, "FP"))
			;
		else if(strcmp_px("ip", src, &src, "IP"))
			;
		else if(strcmp_px("lr", src, &src, "LR"))
			;
		else if(strcmp_px("lsl", src, &src, "LSL("))
			lbrac++;
		else if(strcmp_px("lsr", src, &src, "LSR("))
			lbrac++;
		else if(strcmp_px("pc", src, &src, "PC"))
			;
		else if(strcmp_px("sb", src, &src, "SB"))
			;
		else if(strcmp_px("sl", src, &src, "SL"))
			;
		else if(strcmp_px("sp", src, &src, "SP"))
			;
		else if(('c' == c) || (('p' == c) && !lbrac) || ('r' == c))
		{
			src++;
			vxx = strtol(src, &dst, 0);
			printf("_%c(%u)", c, vxx);
			if(src != dst)
				src = dst;
			else
				ERROR_OUT(src);
		}
		else
			break;

		if(++count > 256)
			break;
	}
	
	while(lbrac--)
		printf(")");
	
	printf("));");
	
	if(src[0])
	{
		printf("\n");
		printf(" /* %s */\n", src);
		return(1);
	}
	
	printf("\n");
	
	return(0);
}

void csx_process(csx_p csx)
{
	uint32_t address = csx->address;
	csx->next_address = address + 4;
	
	cs_data_p csd = &csx->cs_data;

	csd->data = &csx->data[address];
	csd->opcode = (uint32_t*)csd->data;
	
	cs_insn* insn;
	csd->count = cs_disasm(csd->handle, csd->data, 4, address, 0, &insn);
	csd->insn = insn;

	cs_detail* detail = insn->detail;
	
	if (csd->count > 0)
	{
		if(csx_process_op_str(csx))
		{
			csx_disasm_debug(csx);
			exit(0);
			int groups_count = detail->groups_count;
			printf("insn->groups = 0x%02x\n", groups_count);
			if(groups_count)
			{
				for(int i = 0; i < groups_count; i++)
				{
					int group = detail->groups[i];
					const char *groups = "";
					switch(group)
					{
						case	ARM_GRP_V6:
							groups = "ARM_GRP_V6";
							break;
						case	ARM_GRP_V6T2:
							groups = "ARM_GRP_V6T2";
							break;
						case	ARM_GRP_V7:
							groups = "ARM_GRP_V7";
							break;
						case	ARM_GRP_V8:
							groups = "ARM_GRP_V8";
							break;
						case	ARM_GRP_ARM:
							groups = "ARM_GRP_ARM";
							break;
						case	ARM_GRP_PREV8:
							groups = "ARM_GRP_PREV8";
							break;
					}
					printf("insns->group[%02u] = 0x%02x, 0x%02x (%s)\n", i, group, ((group > 128) ? group - 128 : 0), groups);
				}
			}
		}
	}
	else {
		printf("INVALID(0x%08x)\n", address);
		exit(0);
	}

	csx->address = csx->next_address;
}

int main(void)
{
	csx_t ccsx, *csx = &ccsx;
	
	int fd;

	printf("\n\n");
	printf("/*\n");
	printf(" *\n");
	printf(" * opening " LOCAL_RGNDIR RGNFileName "_loader.bin...\n");
	printf(" *\n");
	printf(" */\n\n\n");

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
		csx_process(csx);

	cs_close(&handle);

	return(0);
}
