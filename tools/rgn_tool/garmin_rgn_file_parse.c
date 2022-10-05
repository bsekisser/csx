#include <assert.h>
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

static const uint32_t _ldst = _BV(26);
static const uint32_t _ldr = _ldst | _BV(20);
static const uint32_t _ldr_mask = mlBF(27, 26) | _BV(22) | _BV(20);

static const uint32_t _ldr_pc = _ldr | (0xf << 16);
static const uint32_t _ldr_pc_mask = _ldr_mask | (0x0f << 16);

static uint8_t _rd(uint32_t ir) {
	return(mlBFEXT(ir, 15, 12));
}

/*static uint8_t _rn(uint32_t ir) {
	return(mlBFEXT(ir, 19, 16));
}*/

static void log_ldr_pc_rd(fw_info_p fwi, void* content, void* ip, uint32_t ir)
{
	void* pc = ip + 8;
	uint16_t offset = ir & 0xfff;

	uint32_t base_ip = fwi->base + (ip - content);

	void* src = pc + (BEXT(ir, 23) ? offset : -offset);

	uint32_t base_pc = fwi->base + (src - content);

	if((base_pc + sizeof(uint32_t)) >= fwi->end)
		LOG("out of bounds");

	if(src < content)
		LOG("out of bounds");

	uint32_t data = data_read(src, sizeof(uint32_t));

	if(0xf == _rd(ir)) {
		LOG("0x%08x, 0x%08x[0x%08x]: ldr pc, [pc, %s0x%04x](0x%08x)",
			(uint)ip, base_ip, ir,
			BEXT(ir, 23) ? "" : "-", offset, data);
	} else {
		LOG("0x%08x, 0x%08x[0x%08x]: ldr r%u, [pc, %s0x%04x](0x%08x)",
			(uint)ip, base_ip, ir,
			_rd(ir), BEXT(ir, 23) ? "" : "-", offset, data);
	}
}

static void log_ldr_pc_pc(fw_info_p fwi, void* content, void* ip, uint32_t ir)
{
	log_ldr_pc_rd(fwi, content, ip, ir);
}

/* **** */

static void garmin_rgn_record_app_parse(rgn_record_app_p rar)
{
	uint8_t major = rar->version / 100;
	uint8_t minor = rar->version % 100;

	LOG("version=0x%02x (major=%u, minor=%02u)", rar->version, major, minor);
	
	uint8_t *src = &rar->data[0];
	LOG("builder=%s", strjump(&src));
	LOG("build date=%s", strjump(&src));
	LOG("build time=%s", strjump(&src));
}

static void garmin_rgn_record_data_parse(rgn_record_data_p rdr)
{
	uint8_t major = rdr->version / 100;
	uint8_t minor = rdr->version % 100;
	
	LOG("version=0x%02x (major=%u, minor=%02u)", rdr->version, major, minor);
	
	assert_abort_msg(kRGN_VERSION == rdr->version, "unexpected version");
}

static void garmin_rgn_record_region_parse(rgn_record_region_p rrr)
{
	char *rgn_string = 0, *file_name = 0;
	switch(rrr->version)
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
	
	LOG("region id=0x%02x, %03u (%s)", rrr->version, rrr->version, rgn_string);
	LOG("delay=0x%04x", rrr->delay);
	LOG("size=0x%02x", rrr->size);
	
	if(file_name)
	{
		void *content = &rrr->data[0];
		uint32_t content_size = rrr->size;
		
		LOG("content->0x%08x, size=0x%04x", (uint32_t)content, content_size);
		
		fw_info_t ffwi, *fwi = &ffwi;
		rgn_get_fwinfo(content, content_size, fwi);

		if(0)
		{
			FILE *fout;
			ERR_NULL(fout = fopen(file_name, "w"));
			ERR(fwrite(content, content_size, 1, fout));
		}
		else
		{
			uint32_t opcode;
			int ldr_pc_pc = 0;
			int br = 0;
			int miss = 0;
			
			if(0) for(int i=0; i < content_size; i++)
			{
				void* src = content + i;
				opcode = data_read(src, sizeof(uint32_t));
				if(0xe59ff000 == (opcode & 0xfffff000))
				{
					log_ldr_pc_pc(fwi, content, src, opcode);
					ldr_pc_pc++;
					miss = 0;
					i += sizeof(uint32_t);
				}
				else if(_ldr_pc == (opcode & _ldr_pc_mask))
					log_ldr_pc_rd(fwi, content, src, opcode);
				else if(0xea000000 == (opcode & 0xfe000000))
				{
					br++;
					miss = 0;
					i += sizeof(uint32_t);
				}
				else
				{
					miss++;
					uint32_t score = ldr_pc_pc + br;
					if(miss > 2)
					{
						if(score > 2)
							LOG("i = 0x%08x, score = 0x%08x (ldr_pc_pc = 0x%08x, br = 0x%08x), miss = 0x%08x",
								i, score, ldr_pc_pc, br, miss);
						ldr_pc_pc = 0;
						br = 0;
						miss = 0;
					}
				}
			}
		}
	}
}

static void garmin_rgn_general_record_parse(rgn_general_record_p rgn_record, uint32_t limit)
{
	while((void*)rgn_record < (void*)limit)
	{
		LOG("length=0x%08x", rgn_record->length);
		LOG("id=0x%02x (%c)", rgn_record->id, rgn_record->id);
		void *data = (void *)rgn_record + sizeof(rgn_general_record_t);
		void *next = data + rgn_record->length;
		switch(rgn_record->id) 
		{
			case 'D': /* data record */
			{
				garmin_rgn_record_data_parse(data);
				break;
			}
			case 'A': /* application record */
			{
				garmin_rgn_record_app_parse(data);
				break;
			}
			case 'R': /* region record */
			{
				garmin_rgn_record_region_parse(data);
				break;
			}
			default:
				abort();
		}
		rgn_record = next;
	}
}

static void garmin_rgn_file_parse(void *grf, uint32_t limit)
{
	rgn_file_header_p grfh = (rgn_file_header_p)grf;
	rgn_version_id_p rvid = &grfh->rgn_version_id;
	
	LOG("signature=0x%04x", rvid->signature);
	assert_abort_msg(kRGN_MAGIC == rvid->signature, "invalid signature");

	LOG("version=0x%02x", rvid->version);
	assert_abort_msg(kRGN_VERSION == rvid->version, "unexpected version");

	garmin_rgn_general_record_parse(&grfh->rgn_record, limit);
}

int main(void)
{
	int fd;
	ERR(fd = open(RGNDirPath RGNFileName ".rgn", O_RDONLY));

	struct stat sb;

	ERR(fstat(fd, &sb));
	
	void *data;
	ERR_NULL(data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
	
	garmin_rgn_file_parse(data, (uint32_t)data + sb.st_size);

	munmap(data, sb.st_size);
	close(fd);
}
