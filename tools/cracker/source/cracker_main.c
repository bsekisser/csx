#include "cracker.h"
#include "cracker_arm.h"
#include "cracker_arm_ir.h"
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

int _check_bounds(cracker_p cj, uint32_t pat, uint8_t size, void **p2ptr)
{
	if((pat >= cj->content.base) && ((pat + size) <= cj->content.end))
	{
		if(p2ptr)
			*p2ptr = cj->content.data + (pat - cj->content.base);
		return(1);
	}
	
	return(0);
}

uint32_t _read(cracker_p cj, uint32_t pat, uint8_t size)
{
	uint32_t res = 0;
	uint8_t* src = 0;

	if(!_check_bounds(cj, pat, size, (void*)&src))
	{
//		return(0xdeadbeef);
		return(-1);
		LOG_ACTION(exit(-1));
	}

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

/* **** */

void symbol_enqueue(symbol_h h2sqh, symbol_p lhs, symbol_p cjs, symbol_p rhs)
{
	if(lhs) {
		assert(lhs->pat < cjs->pat);
		lhs->qelem.next = (void*)cjs;
	}

	if(!(*h2sqh))
		*h2sqh = cjs;

	if(rhs)
		assert(rhs->pat > cjs->pat);

	cjs->qelem.next = (void*)rhs;
}

symbol_p symbol_find_pat(symbol_h h2sqh, uint32_t pat, symbol_h lhs, symbol_h rhs)
{
	symbol_p _lhs = 0, _rhs = 0, cjs = *h2sqh;
	
	if(!lhs)
		lhs = &_lhs;

	if(!rhs)
		rhs = &_rhs;
	
	while(cjs) {
		*rhs = (symbol_p)cjs->qelem.next;
			
		if(cjs->pat == pat)
			return(cjs);
			
		if(cjs->pat < pat) {
			*lhs = cjs;

			if(*rhs && ((*rhs)->pat > pat))
				return(0);

		}

		cjs = *rhs;
	}

	return(0);
}

symbol_p symbol_next(symbol_h lhs, symbol_p cjs, symbol_h rhs)
{
	*lhs = cjs;
	cjs = (symbol_p)cjs->qelem.next;

	*rhs = (symbol_p)(cjs ? cjs->qelem.next : 0);

	return(cjs);
}

void symbol_log(cracker_p cj, symbol_p cjs)
{
	LOG_START("0x%08x:", cjs->pat);

	_LOG_(" refs: 0x%04x", cjs->refs);

	if(BTST(cjs->type, SYMBOL_TEXT))
		LOG_END(" TEXT ENTRY");
	
	if(BTST(cjs->type, SYMBOL_DATA)) {
		uint32_t data = 0;
		size_t size = cjs->size;
		
		if(BEXT(size, sizeof(uint32_t)))
			data = _read(cj, cjs->pat, sizeof(uint32_t));
		else if(BEXT(size, sizeof(uint16_t)))
			data = _read(cj, cjs->pat, sizeof(uint16_t));
		else if(BEXT(size, sizeof(uint8_t)))
			data = _read(cj, cjs->pat, sizeof(uint8_t));

		_LOG_(" size: 0x%04x", size);

		if(BXCG(&size, sizeof(uint32_t), 0)) {
			_LOG_(" (uint32_t (0x%08x))%s", data, size ? " |" : "");
		}

		if(BXCG(&size, sizeof(uint16_t), 0)) {
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

void symbol_log_queue(cracker_p cj, symbol_p sqh)
{
	symbol_p cjs = sqh;

	do {
		symbol_log(cj, cjs);

		cjs = (symbol_p)cjs->qelem.next;
	}while(cjs);
}

/* **** */

void cracker_clear(cracker_p cj)
{
	for(int i = 0; i < 16; i++) {
		vGPR(i) = 0;
		GPR(i).src = ~0;
		GPR(i).isPtr = 0;
	}

	for(int i = 0; i < REG_COUNT; i++) {
		rRx(i) = 0;
		vRx(i) = 0;
	}
}

symbol_p cracker_data(cracker_p cj, uint32_t pat, size_t size)
{
	symbol_h sqh = &cj->symbol_qhead;
	
	symbol_p lhs = 0, rhs = 0;
	symbol_p cjs = symbol_find_pat(sqh, pat, &lhs, &rhs);

	if(cjs) {
//		assert(BTST(cjs->size, size));
//		assert(BTST(cjs->type, SYMBOL_DATA));

		BSET(cjs->size, size);
		BSET(cjs->type, SYMBOL_DATA);

		cjs->refs++;
	} else {
		cjs = calloc(1, sizeof(symbol_t));
		
		cjs->pat = pat;
		BSET(cjs->size, size);
		BSET(cjs->type, SYMBOL_DATA);
		
		symbol_enqueue(sqh, lhs, cjs, rhs);
	}

	return(cjs);
}

void cracker_reg_dst(cracker_p cj, uint8_t r)
{
	if(!cj->symbol)
		return;

	BSET(cj->symbol->reg.dst, r);
}

void cracker_reg_src(cracker_p cj, uint8_t r)
{
	if(!cj->symbol)
		return;

	BSET(cj->symbol->reg.src, r);
}

static int cracker_step(cracker_p cj)
{
	IP = PC;

	if(IP & 1)
		return(thumb_step(cj));

	return(arm_step(cj));
}

symbol_p cracker_text(cracker_p cj, uint32_t pat)
{
	symbol_h sqh = &cj->symbol_qhead;

	symbol_p lhs = 0, rhs = 0;
	symbol_p cjs = symbol_find_pat(sqh, pat, &lhs, &rhs);

	if(cjs) {
//		assert(BTST(cjs->size, sizeof(uint32_t)));
//		assert(BTST(cjs->type, SYMBOL_TEXT));

		BSET(cjs->size, sizeof(uint32_t));
		BSET(cjs->type, SYMBOL_TEXT);

		cjs->refs++;
	} else {
		cjs = calloc(1, sizeof(symbol_t));
		
		cjs->pat = pat;
		BSET(cjs->size, sizeof(uint32_t));
		BSET(cjs->type, SYMBOL_TEXT);
		
		symbol_enqueue(sqh, lhs, cjs, rhs);

		if(!_check_bounds(cj, pat, sizeof(uint32_t), 0))
			cjs->pass++;

		if(cj->symbol && (cj->symbol->pat <= pat)) {
			if(PC >= pat) {
//			if(IP >= pat) {
				cjs->pass += (0 == cjs->pass);
			}
		}
	}

	if(0) if(cjs) {
		if(cj->symbol->pat <= pat) {
			if(PC >= pat) {
				cjs->pass++;
			}
		}
	}

	return(cjs);
}

/* **** */

int main(void)
{
	int fd;
//	ERR(fd = open(RGNDirPath RGNFileName "_loader.bin", O_RDONLY));
	ERR(fd = open(RGNDirPath RGNFileName "_firmware.bin", O_RDONLY));

	struct stat sb;

	ERR(fstat(fd, &sb));
	
	void *data;
	ERR_NULL(data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));

	close(fd);
	
	cracker_t cjt, *cj = &cjt;
	
	cjt.content.data = data;
	cjt.content.base = 0x10020000;
	cjt.content.size = sb.st_size;
	cjt.content.end = cjt.content.base + cjt.content.size;
	
	cracker_clear(cj);

	PC = cjt.content.base;
	
	LOG("Loaded: " RGNFileName "_loader.bin... Start: 0x%08x, End: 0x%08x",
		cjt.content.base, cjt.content.end);
	
	cjt.symbol = cracker_text(cj, PC);
	cjt.symbol_pass = 0;
	cjt.symbol->pass++;

	while(cjt.symbol) {
		if(!cracker_step(cj)) {
			cracker_clear(cj);

//			CORE_TRACE();
			printf("\n");
			cjt.symbol = 0;
			symbol_p cjs = cj->symbol_qhead;
			
			do {
				if(cjs) {
					if(BTST(cjs->type, SYMBOL_TEXT)) {
						if(!cjs->pass) {
							cjt.symbol = cjs;

							cjs->pass++;
							PC = cjs->pat;
						}
					}
					
					cjs = (symbol_p)cjs->qelem.next;
				} else
					break;

			}while(!cjt.symbol);
		}
	};

	CORE_TRACE("/* **** **** **** **** */");

	printf("\n\n/* **** **** **** **** */\n\n");

	symbol_log_queue(cj, cj->symbol_qhead);

	munmap(data, sb.st_size);
}
