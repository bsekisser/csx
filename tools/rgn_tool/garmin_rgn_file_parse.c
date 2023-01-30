#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"
#include "shift_roll.h"

/* **** */

#include "garmin_rgn_file.h"

#include "fwinfo.h"

/* **** */

//#define RGNDirPath "../../../garmin/rgn_files/"
#define RGNDirPath "../../../garmin/rgn_files/"

//#define RGNFileName "029201000350" /* xxx */

#define RGNFileName "038201000610"
//#define RGNFileName "038201000280"

//#define RGNFileName "048101000610"

//#define RGNFileName "049701000610"

/* **** */

static uint32_t data_read(void* p2src, uint8_t size)
{
	uint32_t res = 0;
	uint8_t* src = p2src;

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

static uint8_t* strjump(uint8_t **str)
{
	uint8_t *src = *str;
	
	(*str) += strlen((char*)src) + 1;
	
	return(src);
}

/* **** */

enum {
	rSP = 13,
	rLR = 14,
	rPC = 15,
};

typedef struct grf_t* grf_p;
typedef struct grf_t {
	uint32_t ip;
	uint32_t ir;
	uint32_t pc;

	void* data;
	void* data_content;
	void* data_content_end;
	size_t data_content_size;
	void* data_end;
	size_t data_size;

	fw_info_t fwi;
}grf_t;

#define ARM_PC ((IP & ~3) + 8)

#define IP grf->ip
#define IR grf->ir
#define PC grf->pc

static uint32_t base_ip(grf_p grf)
{
	return(grf->fwi.base + IP);
}

static uint32_t ld32le(grf_p grf, uint32_t pat)
{
	if(pat > grf->data_content_size)
		return(-1);
	
	void* src = grf->data_content + pat;

	if((src + sizeof(uint32_t)) < grf->data_content_end)
		return(data_read(src, sizeof(uint32_t)));
	
	return(-1);
}

static const uint32_t _rd_mask = mlBF(15, 12);
static const uint32_t _rn_mask = mlBF(19, 16);

static const uint32_t _cc_al = mlBF(31, 29);
static const uint32_t _cc_mask = mlBF(31, 28);

static const uint32_t _b = _cc_al | _BV(27) | _BV(25);
static const uint32_t _b_mask = _cc_mask | mlBF(27, 24);

static const uint32_t _dpi = _cc_al | _BV(25);
//static const uint32_t _dpi_mask = mlBF(27, 25);
static const uint32_t _dpi_mask = _cc_mask | mlBF(27, 21);

static const uint32_t _ldst = _cc_al | _BV(26);
static const uint32_t _ldst_bit_u = _BV(23);

static const uint32_t _ldr = _ldst | _BV(20);
static const uint32_t _ldr_mask = _cc_mask | mlBF(27, 26) | _BV(22) | _BV(20);
static const uint32_t _ldr_rn_mask = _ldr_mask | _rn_mask;
static const uint32_t _ldr_rd_rn_mask = _ldr_rn_mask | _rd_mask;

static const uint32_t _mov_op = 0b1101 << 21;

static const uint32_t _movi = _dpi | _mov_op;
static const uint32_t _movi_rd_mask = _dpi_mask | _rd_mask; 


static uint32_t _arm_ldst_bit_u(uint32_t ir) {
	return(BEXT(ir, _ldst_bit_u));
}

static uint32_t _arm_rd(uint32_t rd) {
	return((rd & 0xf) << 12);
}

static uint32_t _arm_rn(uint32_t rn) {
	return((rn & 0xf) << 16);
}

static uint32_t arm_ldr_rn(uint8_t rn) {
	return(_ldr | _arm_rn(rn));
}

static uint32_t arm_ldr_rd_rn(uint8_t rd, uint8_t rn) {
	return(arm_ldr_rn(rn) | _arm_rd(rd));
}

static uint32_t arm_movi_rd(uint8_t rd) {
	return(_movi | _arm_rd(rd));
}

static uint8_t arm_ir_rd(uint32_t ir) {
	return(mlBFEXT(ir, 15, 12));
}

static uint8_t arm_ir_rn(uint32_t ir) {
	return(mlBFEXT(ir, 19, 16));
}

static void log_b(grf_p grf)
{
	int32_t offset = mlBFMOVs(IR, 23, 0, 2);
	uint32_t pat = ARM_PC + offset;

	uint32_t pat_ip = (base_ip(grf) + 8) + offset;

	LOG("0x%08x, 0x%08x[0x%08x]: b 0x%08x%s",
		IP, base_ip(grf), IR, pat, ((pat_ip == base_ip(grf)) ? " << ZZZZ" : ""));
}

static void log_ldr_rd_rn(grf_p grf)
{
	int _bit_u = _arm_ldst_bit_u(IR);

	int16_t offset = mlBFEXT(IR, 11, 0);
	if(_bit_u)
		offset = -offset;

	uint32_t pat = ARM_PC + offset;
	uint32_t pat_ip = (base_ip(grf) + 8) + offset;

	uint32_t data = ld32le(grf, pat);

	LOG("0x%08x, 0x%08x[0x%08x]: ldr r%u, [r%u, 0x%04x] /* [0x%08x]:0x%08x */%s",
		IP, base_ip(grf), IR,
			arm_ir_rd(IR), arm_ir_rn(IR), offset, pat, data,
			((pat_ip == base_ip(grf)) ? " << ZZZZ" : ""));
}

static void log_movi_rd(grf_p grf)
{
	uint8_t imm8 = mlBFEXT(IR, 7, 0);
	uint8_t shift = mlBFMOV(IR, 11, 8, 1);
	
	uint32_t data = _ror(imm8, shift);
	
	LOG("0x%08x, 0x%08x[0x%08x]: mov r%u, #0x%08x",
		IP, base_ip(grf), IR,
			arm_ir_rd(IR), data);
}

/* **** */

static void garmin_rgn_record_app_parse(grf_p grf, rgn_record_app_p rar)
{
	uint16_t version = le16toh(rar->version);

	uint8_t major = version / 100;
	uint8_t minor = version % 100;

	LOG("version=0x%04x (major=%u, minor=%02u)", version, major, minor);
	
	uint8_t *src = &rar->data[0];
	LOG("builder=%s", strjump(&src));
	LOG("build date=%s", strjump(&src));
	LOG("build time=%s", strjump(&src));
}

static void garmin_rgn_record_data_parse(grf_p grf, rgn_record_data_p rdr)
{
	uint16_t version = le16toh(rdr->version);

	uint8_t major = version / 100;
	uint8_t minor = version % 100;
	
	LOG("version=0x%04x (major=%u, minor=%02u)", version, major, minor);
	
	assert_abort_msg(kRGN_VERSION == rdr->version, "unexpected version");
}

static void garmin_rgn_record_region_parse_bin(grf_p grf, void* pat)
{
	
	for(PC = 0; PC < grf->data_content_size; PC += sizeof(uint32_t))
	{
		IP = PC;
		IR = ld32le(grf, IP);

//		if(0xeafffffe == IR)
//			log_b(grf);
		if(_b == (IR & _b_mask))
//		else if(_b == (IR & _b_mask))
			log_b(grf);
//		else if(arm_ldr_rd_rn(rPC, rPC) == (IR & _ldr_rd_rn_mask))
//			log_ldr_rd_rn(grf);
//		else if(arm_ldr_rn(rPC) == (IR & _ldr_rn_mask))
//			log_ldr_rd_rn(grf);
		else if(arm_movi_rd(rSP) == (IR & _movi_rd_mask))
			log_movi_rd(grf);
	}
}

static void garmin_rgn_record_region_parse(grf_p grf, rgn_record_region_p rrr)
{
	char *rgn_string = 0, *file_name = 0;
	uint16_t version = le16toh(rrr->version);
	switch(version)
	{
		case RGN_TYPE_LOADER:
			rgn_string = "loader";
			file_name = RGNFileName "_loader.bin";
			break;
		case RGN_TYPE_FW_ALL:
			rgn_string = "firmware";
			file_name = RGNFileName "_firmware.bin";
			break;
		default:
			rgn_string = "unknown";
			file_name = 0;
			break;
	}
	
	LOG("region id = 0x%04x, %05u (%s)", version, version, rgn_string);
	LOG("delay = 0x%08x", le32toh(rrr->delay));

	size_t size = le32toh(rrr->size);

	LOG("size = 0x%08x", size);
	
	if(file_name)
	{
		grf->data_content = &rrr->data[0];
		grf->data_content_size = size;
		grf->data_content_end = grf->data_content + size;
		
		LOG("content->0x%08x, size = 0x%08x",
			(uint32_t)grf->data_content, grf->data_content_size);
		
		rgn_get_fwinfo(grf->data_content, grf->data_content_size, &grf->fwi);

		if(0)
		{
			FILE *fout;
			ERR_NULL(fout = fopen(file_name, "w"));
			ERR(fwrite(grf->data_content, grf->data_content_size, 1, fout));
		}
		else
			garmin_rgn_record_region_parse_bin(grf, grf->data_content);
	}
}

static void garmin_rgn_general_record_parse(grf_p grf, rgn_general_record_p rgn_record)
{
	while(((void*)rgn_record + sizeof(rgn_general_record_t)) <= grf->data_end)
	{
		uint32_t length = le32toh(rgn_record->length);
		
		LOG("length = 0x%08x", length);
		LOG("id = 0x%02x (%c)", rgn_record->id, rgn_record->id);
		void *data = (void *)rgn_record + sizeof(rgn_general_record_t);
		void *next = data + length;
		switch(rgn_record->id) 
		{
			case 'D': /* data record */
			{
				garmin_rgn_record_data_parse(grf, data);
				break;
			}
			case 'A': /* application record */
			{
				garmin_rgn_record_app_parse(grf, data);
				break;
			}
			case 'R': /* region record */
			{
				garmin_rgn_record_region_parse(grf, data);
				break;
			}
			default:
				abort();
		}
		rgn_record = next;
	}
}

static void garmin_rgn_file_parse(grf_p grf)
{
	rgn_file_header_p grfh = (rgn_file_header_p)grf->data;
	rgn_version_id_p rvid = &grfh->rgn_version_id;
	
	uint32_t signature = le32toh(rvid->signature);

	LOG("signature = 0x%08x", signature);
	assert_abort_msg(kRGN_MAGIC == signature, "invalid signature");

	uint16_t version = le16toh(rvid->version);

	LOG("version=0x%04x", version);
	assert_abort_msg(kRGN_VERSION == version, "unexpected version");

	garmin_rgn_general_record_parse(grf, &grfh->rgn_record);
}

int main(void)
{
	LOG("0x%08x", arm_movi_rd(0));
	LOG("0x%08x", arm_movi_rd(15));
	LOG("0x%08x", _movi_rd_mask);
	
	grf_p grf = calloc(1, sizeof(grf_t));
	
	int fd;
	ERR(fd = open(RGNDirPath RGNFileName ".rgn", O_RDONLY));

	struct stat sb;

	ERR(fstat(fd, &sb));

	ERR_NULL(grf->data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
	
	close(fd);

	grf->data_end = grf->data + sb.st_size;
	grf->data_size = sb.st_size;

	/* **** */

	garmin_rgn_file_parse(grf);

	/* **** */

	munmap(grf->data, sb.st_size);
	free(grf);
}
