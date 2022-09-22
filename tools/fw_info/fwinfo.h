#include <stddef.h>
#include <stdint.h>

typedef struct fw_info_t* fw_info_p;
typedef struct fw_info_t {
	uint32_t base;
	uint32_t end;
	uint16_t* hwid;
	uint16_t* swvr;
}fw_info_t;

void rgn_get_fwinfo(void* content, size_t content_size, fw_info_p p2fwi);
