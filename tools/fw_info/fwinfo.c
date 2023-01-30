#include <assert.h>
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* **** */

#include "fwinfo.h"

#include "log.h"

/* **** */

#ifndef uint
	typedef unsigned int uint;
#endif

typedef struct bfc_t* bfc_p;
typedef struct bfc_t {
	uint32_t b;
	union {
		union { /* 0xe59ff008 */
			struct {
				uint32_t	end;
				uint32_t	hwid;
				uint32_t	sw_version;
				uint32_t	entrypoint;
			}a;
			struct { /* hwid & sw_version differ by two */
				uint32_t	hwid;
				uint32_t	sw_version;
				uint32_t	end;
				uint32_t	entrypoint;
			}b;
		}v1;
		struct { /* 0xe59ff00c */
			uint32_t	end;
			uint32_t	hwid;
			uint32_t	sw_version;
			int32_t		loadAddress_lend; /* <0 load addresss, else lend */
			uint32_t	entrypoint;
		}v2;
		struct { /* 0xea000002 */
			uint32_t	end;
			uint32_t	hwid;
			uint32_t	sw_version;
		}v3;
		struct { /* 0xea000003 */
			uint32_t	end;
			uint32_t	hwid;
			uint32_t	sw_version;
			uint32_t	unknown;
		}v4;
	};
}__attribute__((packed)) bfc_t;

//static uint8_t fw_end_marker[] = { 0xff, 0xff, 0x5a, 0xa5 };
static uint8_t fw_end_marker[] = { 0xff, 0xff, 0x5a, 0xa5,
									0xff, 0xff, 0xff, 0xff };

static void* fp_bin_search(
	uint8_t *data,
	uint32_t fp_size,
	uint8_t *match,
	uint32_t match_len)
{
	if (fp_size <=  match_len)
		return(0);
	
	uint8_t *fpp = data + (fp_size - match_len);
	for(; fpp >= data; fpp--) 
	{
		if (0 == memcmp(fpp, match, match_len))
			return(fpp);
	}

	return(0);
}

void rgn_get_fwinfo(void* content, size_t content_size, fw_info_p fwi)
{
	bfc_p bfc = content;

	LOG("[0] = 0x%08x", le32toh(bfc->b));
	
	switch(bfc->b) {
		case 0xea000002:
		case 0xea000003: {
			void* fw_mark = fp_bin_search(content, content_size, fw_end_marker, sizeof(fw_end_marker));
			fw_mark += 2;
			
			assert(0 != fw_mark);

			LOG("fw_mark = 0x%08x", (uint)fw_mark);

			fwi->base = le32toh(bfc->v3.end) - (fw_mark - content);
	
			LOG("fwi->base = 0x%08x", fwi->base);
			
			assert(0 == (fwi->base % 4));
			assert(!((fwi->base + content_size) < fwi->base));
			
			fwi->end = le32toh(bfc->v3.end);
			
			LOG("content_size - end - base = 0x%08x", content_size - (fwi->end - fwi->base));
			
			uint32_t p2hwid = le32toh(bfc->v3.hwid);
			fwi->hwid = (uint16_t*)((content + p2hwid) - fwi->base);
			uint16_t hwid = le16toh(*fwi->hwid);

			uint32_t p2swvr = le32toh(bfc->v3.sw_version);
			fwi->swvr = (uint16_t*)((content + p2swvr) - fwi->base);
			uint16_t swvr = le16toh(*fwi->swvr);

			LOG("end @ 0x%08x", fwi->end);
			LOG("hwid @ 0x%08x = 0x%04x = %u", p2hwid, hwid, hwid);
			LOG("sw_version @ 0x%08x = 0x%04x = %u", p2swvr, swvr, swvr);
		}break;
		default:
			LOG("unknown version");
			exit(-1);
			break;
	};
}
