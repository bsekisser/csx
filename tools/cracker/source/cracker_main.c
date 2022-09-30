#include "cracker.h"
#include "cracker_arm.h"
#include "cracker_strings.h"
#include "cracker_thumb.h"
#include "cracker_trace.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"
#include "shift_roll.h"

/* **** */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* **** */

//#define RGNDirPath "../../../garmin/rgn_files/"
#define RGNDirPath "../../../garmin/rgn_files/"

//#define RGNFileName "029201000350" /* xxx */

#define RGNFileName "038201000610"
//#define RGNFileName "038201000280"

//#define RGNFileName "048101000610"

//#define RGNFileName "049701000610"

/* **** */

uint32_t _read(cracker_p cj, uint32_t pat, uint8_t size)
{
	uint32_t res = 0;
	uint8_t* src = 0;

	uint content_end = cj->content_base + cj->content_size;

	if((pat >= cj->content_base) && ((pat + size) <= content_end))
		src = cj->content + (pat - cj->content_base);
	else
		LOG_ACTION(exit(-1));

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

/* **** */

symbol_p symbol_find_pat(cracker_p cj, uint32_t pat, symbol_h lhs, symbol_h rhs)
{
	symbol_p cjs = cj->symbol_qhead;
	
	do {
		if(cjs) {
			*rhs = (symbol_p)cjs->qelem.next;
			
//			LOG("cjs[0x%08x]->pat = 0x%08x", (uint)cjs, cjs->pat);
			
			if(cjs->pat == pat)
				return(cjs);
			
			if(cjs->pat < pat) {
				*lhs = cjs;

				if(*rhs && ((*rhs)->pat > pat))
						return(0);

			}
		}

		cjs = *rhs;
	}while(*rhs);

	return(0);
}

void symbol_enqueue(cracker_p cj, symbol_p lhs, symbol_p cjs, symbol_p rhs)
{
	if(lhs) {
		assert(lhs->pat < cjs->pat);
		lhs->qelem.next = (void*)cjs;
	}

	if(!cj->symbol_qhead)
		cj->symbol_qhead = cjs;

	if(rhs)
		assert(rhs->pat > cjs->pat);

	cjs->qelem.next = (void*)rhs;
}

void symbol_log(cracker_p cj, symbol_p cjs)
{
	LOG_START("0x%08x:", cjs->pat);
	if(BTST(cjs->type, SYMBOL_TEXT))
		LOG_END(" TEXT ENTRY");
	else {
		uint32_t data = 0;
		size_t size = cjs->size;
		
		if(BEXT(size, sizeof(uint32_t)))
			data = _read(cj, cjs->pat, sizeof(uint32_t));
		else if(BEXT(size, sizeof(uint16_t)))
			data = _read(cj, cjs->pat, sizeof(uint16_t));
		else if(BEXT(size, sizeof(uint8_t)))
			data = _read(cj, cjs->pat, sizeof(uint8_t));

		_LOG_(" size: 0x%04x", size);

		if(BXCG(size, sizeof(uint32_t), 0)) {
			_LOG_(" (uint32_t (0x%08x))%s", data, size ? " |" : "");
		}

		if(BXCG(size, sizeof(uint16_t), 0)) {
			_LOG_(" (uint16_t (0x%04x))%s", (uint16_t)data, size ? " |" : "");
//			_LOG_(" uint16_t%s", size ? " |" : "");
		}
			
		if(BTST(size, sizeof(uint8_t))) {
			_LOG_(" (uint8_t (0x%02x))", (uint8_t)data);
//			_LOG_(" uint8_t");
		}

		LOG_END();
//		LOG_END(": 0x%08x", data);
	}
}

/* **** */


void cracker_data(cracker_p cj, uint32_t pat, size_t size)
{
	symbol_p lhs = 0, rhs = 0;
	symbol_p cjs = symbol_find_pat(cj, pat, &lhs, &rhs);

	if(cjs) {
//		symbol_log(cj, cjs);
		assert(BTST(cjs->size, size));
		assert(BTST(cjs->type, SYMBOL_DATA));
	} else {
		cjs = calloc(1, sizeof(symbol_t));
		
		cjs->pat = pat;
		BSET(cjs->size, size);
		BSET(cjs->type, SYMBOL_DATA);
		
		symbol_enqueue(cj, lhs, cjs, rhs);
	}
}

static int cracker_step(cracker_p cj)
{
	IP = PC;

	if(IP & 1)
		return(thumb_step(cj));

	return(arm_step(cj));
}

void cracker_text(cracker_p cj, uint32_t pat)
{
	symbol_p lhs = 0, rhs = 0;
	symbol_p cjs = symbol_find_pat(cj, pat, &lhs, &rhs);

	if(cjs) {
//		symbol_log(cj, cjs);
		assert(BTST(cjs->size, sizeof(uint32_t)));
		assert(BTST(cjs->type, SYMBOL_TEXT));
	} else {
		cjs = calloc(1, sizeof(symbol_t));
		
		cjs->pat = pat;
		BSET(cjs->size, sizeof(uint32_t));
		BSET(cjs->type, SYMBOL_TEXT);
		
		symbol_enqueue(cj, lhs, cjs, rhs);
	}
}

/* **** */

int main(void)
{
	int fd;
	ERR(fd = open(RGNDirPath RGNFileName "_loader.bin", O_RDONLY));

	struct stat sb;

	ERR(fstat(fd, &sb));
	
	void *data;
	ERR_NULL(data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));

	close(fd);
	
	cracker_t cjt, *cj = &cjt;
	
	cjt.content = data;
	cjt.content_base = 0x10020000;
	cjt.content_size = sb.st_size;
	PC = cjt.content_base;
	
	cracker_text(cj, PC);
	
	for(;;) {
		if(!cracker_step(cj)) {
			symbol_p cjs = symbol_find_pat(cj, PC, lhs, 0, rhs);

			do {
				if(cjs && BTST(cjs->type, SYMBOL_TEXT))
					PC = cjs->pat;
					break;
				
				
			}while(rhs);
			else
			break;
	};

	CORE_TRACE();

	symbol_p cjs = cj->symbol_qhead;
	if(cjs) do {
		symbol_log(cj, cjs);

		cjs = (symbol_p)cjs->qelem.next;
	}while(cjs);

	munmap(data, sb.st_size);
}
