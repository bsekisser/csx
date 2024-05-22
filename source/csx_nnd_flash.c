#include "csx_nnd_flash.h"

/* **** */

#include "csx.h"

/* **** */

#include "libarmvm/include/armvm_mem.h"

#include "libbse/include/bitfield.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/mem_access_le.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct csx_nnd_unit_t* csx_nnd_unit_p;
typedef struct csx_nnd_unit_t {
	uint32_t						addr;
	uint32_t						cl;
	unsigned						cs;
	uint32_t						status;
//
	csx_p							csx;
	csx_nnd_p						nnd;
}csx_nnd_unit_t;

typedef struct csx_nnd_t {
	csx_p							csx;

	csx_nnd_unit_t					unit[16];

	char							flash[1 << 12];

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}csx_nnd_t;

/* **** */

enum {
	RWD = 0x00,
	CLE = 0x02,
	ALE = 0x04,
};

const uint8_t csx_nnd_flash_part_id[] = {
	0x79,	/* 1Gb/128MB */
	0x76,	/* 512Mb/64MB */
	0x75,	/* 256Mb/32MB */
	0x73,	/* 128Mb/16MB */
};

const uint8_t csx_nnd_flash_manufacturer_code[] = {
	0xec,	/* samsung */
	0x98,	/* toshiba */
	0x04,	/* fujitsu */
};

#define CSx_LSB 24
#define OFFSET_MSB (CSx_LSB - 1)

const uint8_t csx_nnd_flash_id[16][5] = {
//	[0x4] = { 0xec, 0x77, 0x51, 0x95, 0x58 },
//	[0x8] = { 0xec, 0x73, 0x51, 0x95, 0x58 },
//	[0xc] = { 0xec, 0x00, 0x51, 0x95, 0x58 },
	[0xc] = { 0xec, 0x77 + 8, 0x51, 0x95, 0x58 }, // <<!
//	[0xc] = { 0xec, 0x78, 0x51, 0x95, 0x58 },
//
//	0xec, 0xd3, 0x51, 0x95, 0x58
//
//	csx_nnd_flash_part_id[0],
//	csx_nnd_flash_manufacturer_code[0],
};

/* **** */

/*
 * 0200 0000 -- 2 -- 0010
 * 0400 0000 -- 4 -- 0100
 * 0800 0000 -- 8 -- 1000
 * 0C00 0000 -- C -- 1100
 *   00 16
 *   0\ 20
 * 	 \  24
 */

static int __csx_nnd_flash_atexit(void* param)
{
	if(_trace_atexit) {
		LOG(">>");
	}

	handle_free(param);

	if(_trace_atexit_pedantic) {
		LOG("<<");
	}

	return(0);
}

static uint32_t _csx_nnd_flash_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write) {
	if(write)
		csx_nnd_flash_write(param, ppa, size, *write);
	else
		return(csx_nnd_flash_read(param, ppa, size));

	return(0);
}

static csx_nnd_unit_p _csx_nnd_flash_unit(csx_nnd_p nnd, uint32_t addr, unsigned* p2cs)
{
	const unsigned cs = addr >> CSx_LSB;

	assert(cs < 16);

	if(p2cs)
		*p2cs = cs;

//	return(0);
	const csx_nnd_unit_p unit = &nnd->unit[cs];

	if(0) {
		LOG_START("");

		if(0) {
			_LOG_("nnd = 0x%08" PRIxPTR, (uintptr_t)nnd);
			_LOG_(", unit = 0x%08" PRIxPTR, (uintptr_t)unit);
			_LOG_(", ");
		}

		_LOG_("addr = 0x%08x", addr);
		_LOG_(", cs = 0x%02x", cs);

		LOG_END();
	}

	return(unit);
}

/* **** */


csx_nnd_p csx_nnd_flash_alloc(csx_p csx, csx_nnd_h h2nnd)
{
	ERR_NULL(csx);
	ERR_NULL(h2nnd);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	csx_nnd_p nnd = HANDLE_CALLOC(h2nnd, 1, sizeof(csx_nnd_t));
	ERR_NULL(nnd);

	nnd->csx = csx;

	/* **** */

	csx_callback_atexit(csx, &nnd->atexit, __csx_nnd_flash_atexit, h2nnd);

	/* **** */

	for(unsigned cs = 0; cs < 16; cs++) {
		csx_nnd_unit_p unit = &nnd->unit[cs];
		unit->cs = cs;
		unit->csx = csx;
		unit->nnd = nnd;
	}

	/* **** */

	return(nnd);
}

void csx_nnd_flash_init(csx_nnd_p nnd)
{
	ERR_NULL(nnd);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	strcpy(&nnd->flash[0x10], "DSKIMG");

	nnd->flash[0x17] = 6;
	nnd->flash[0x18] = 8;
	nnd->flash[0x1a] = 12;
	nnd->flash[0x24] = 8;

	/* **** */

	csx_p csx = nnd->csx;
	armvm_mem_p mem = csx->armvm->mem;

	armvm_mem_mmap(mem, 0x02000000, 0x03ffffff, _csx_nnd_flash_mem_access, nnd);
	armvm_mem_mmap(mem, 0x04000000, 0x07ffffff, _csx_nnd_flash_mem_access, nnd);
	armvm_mem_mmap(mem, 0x08000000, 0x0bffffff, _csx_nnd_flash_mem_access, nnd);
	armvm_mem_mmap(mem, 0x0c000000, 0x0fffffff, _csx_nnd_flash_mem_access, nnd);

	/* **** */
}

uint32_t csx_nnd_flash_read(csx_nnd_p nnd, uint32_t addr, size_t size)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	if(0) LOG("addr = 0x%08x, offset = 0x%08x, size = 0x%08zx",
		addr, offset, size);

	unsigned cs = 0;
	const csx_nnd_unit_p unit = _csx_nnd_flash_unit(nnd, addr, &cs);

	if(0 == unit) {
		LOG("addr = 0x%08x, cs = 0x%08x, offset = 0x%08x, size = 0x%08zx",
			addr, cs, offset, size);

		return(0);
	}

	unsigned cl_index = unit->addr;
	unsigned value =  addr & 0xff;

	switch(offset) {
		case RWD:
			switch(unit->cl & 0xff) {
				case 0x70: /* read status */
					value = unit->status;
				break;
				case 0x90: /* read id */
					value = mem_access_le((void *const)&csx_nnd_flash_id[cs][cl_index], size, 0);
					cl_index += size;
					unit->addr = cl_index < 5 ? cl_index : 0;
				break;
			}
			break;
		default:
			value = mem_access_le(&nnd->flash[addr & 0xfff], size, 0);
//			LOG("addr = 0x%08x, cs = 0x%08x, value = 0x%08x, size = 0x%08zx, cl = 0x%08x",
//				addr, cs, value, size, unit->cl);
			break;
	}

	if(0) LOG("addr = 0x%08x, cs = 0x%08x, size = 0x%08zx, cl = 0x%08x:0%08x, value = 0x%08x",
		addr, cs, size, unit->cl, unit->addr, value);

	return(value);
}

static void csx_nnd_flash_write_cle(csx_nnd_p nnd, csx_nnd_unit_p unit, size_t size, uint32_t value)
{
	unsigned cs = unit->cs;

	if(0) LOG("cs = 0x%08x, value = 0x%08x, size = 0x%08zx, cl = 0x%08x", cs, value, size, unit->cl);

	if(0xff == value) { /* reset */
		unit->addr = 0;
		unit->cl = 0;
		unit->status = 0;
		BSET(unit->status, 7); /* not write protected */
		BSET(unit->status, 6); /* device ready */
	} else {
//		unit->addr = 0;
		unit->cl <<= 8;
		unit->cl |= (value & 0xff);
	}

	if(0) LOG("cs = 0x%08x, value = 0x%08x, size = 0x%08zx, cl = 0x%08x", cs, value, size, unit->cl);

	UNUSED(nnd);
}

void csx_nnd_flash_write(csx_nnd_p nnd, uint32_t addr, size_t size, uint32_t value)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	unsigned cs = 0;
	const csx_nnd_unit_p unit = _csx_nnd_flash_unit(nnd, addr, &cs);

	if(0 == unit) {
		LOG("addr = 0x%08x, cs = 0x%08x, offset = 0x%08x, size = 0x%08zx, value = 0x%08x",
			addr, cs, offset, size, value);

		return;
	}

	switch(offset) {
		case ALE:
			unit->addr = value;
			break;
		case CLE:
			if(0) LOG("CLE: value = 0x%08x, size = 0x%08zx", value, size);
			csx_nnd_flash_write_cle(nnd, unit, size, value);
			break;
		default:
			LOG("addr = 0x%08x, cs = 0x%08x, offset = 0x%08x, value = 0x%08x, size = 0x%08zx",
				addr, cs, offset, value, size);
			break;
	}
}
