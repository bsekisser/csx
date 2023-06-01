#include "soc_nnd_flash.h"

/* **** */

#include "csx.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_nnd_unit_t* soc_nnd_unit_p;
typedef struct soc_nnd_unit_t {
	csx_p							csx;
	soc_nnd_p						nnd;
	uint32_t						cl;
	unsigned						cl_index;
	unsigned						cs;
	uint32_t						status;
}soc_nnd_unit_t;

typedef struct soc_nnd_t {
	csx_p							csx;

	soc_nnd_unit_t					unit[16];
}soc_nnd_t;

/* **** */

enum {
	RWD = 0x00,
	CLE = 0x02,
	ALE = 0x04,
};

const uint8_t soc_nnd_flash_part_id[] = {
	0x79,	/* 1Gb/128MB */
	0x76,	/* 512Mb/64MB */
	0x75,	/* 256Mb/32MB */
	0x73,	/* 128Mb/16MB */
};

const uint8_t soc_nnd_flash_manufacturer_code[] = {
	0xec,	/* samsung */
	0x98,	/* toshiba */
	0x04,	/* fujitsu */
};

#define CSx_LSB 24
#define OFFSET_MSB (CSx_LSB - 1)

const uint8_t soc_nnd_flash_id[16][5] = {
//	[0x4] = { 0xec, 0x77, 0x51, 0x95, 0x58 },
//	[0x8] = { 0xec, 0x73, 0x51, 0x95, 0x58 },
//	[0xc] = { 0xec, 0x77, 0x51, 0x95, 0x58 }, // <<!
	[0xc] = { 0xec, 0x78, 0x51, 0x95, 0x58 },
//
//	0xec, 0xd3, 0x51, 0x95, 0x58
//
//	soc_nnd_flash_part_id[0],
//	soc_nnd_flash_manufacturer_code[0],
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

static int _soc_nnd_flash_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	handle_free(param);

	return(0);
}

static uint32_t _soc_nnd_flash_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write) {
	if(write)
		soc_nnd_flash_write(param, ppa, size, *write);
	else
		return(soc_nnd_flash_read(param, ppa, size));

	return(0);
}

static soc_nnd_unit_p _soc_nnd_flash_unit(soc_nnd_p nnd, uint32_t addr, unsigned* p2cs)
{
	const unsigned cs = addr >> CSx_LSB;

	assert(cs < 16);

	if(p2cs)
		*p2cs = cs;

//	return(0);
	const soc_nnd_unit_p unit = &nnd->unit[cs];

	if(0) {
		LOG_START("");

		if(0) {
			_LOG_("nnd = 0x%08" PRIxPTR, (uintptr_t)nnd);
			_LOG_(", unit = 0x%08x" PRIxPTR, (uintptr_t)unit);
			_LOG_(", ");
		}

		_LOG_("addr = 0x%08x", addr);
		_LOG_(", cs = 0x%02x", cs);

		LOG_END();
	}

	return(unit);
}

/* **** */

int soc_nnd_flash_init(csx_p csx, soc_nnd_h h2nnd)
{
	assert(0 != csx);
	assert(0 != h2nnd);

	if(_trace_init) {
		LOG();
	}

	soc_nnd_p nnd = HANDLE_CALLOC(h2nnd, 1, sizeof(soc_nnd_t));
	ERR_NULL(nnd);

	nnd->csx = csx;

	for(unsigned cs = 0; cs < 16; cs++) {
		soc_nnd_unit_p unit = &nnd->unit[cs];
		unit->cs = cs;
		unit->csx = csx;
		unit->nnd = nnd;
	}

	/* **** */

	csx_callback_atexit(csx, _soc_nnd_flash_atexit, h2nnd);

	csx_mem_mmap(csx, 0x02000000, 0x03ffffff, _soc_nnd_flash_mem_access, nnd);
	csx_mem_mmap(csx, 0x04000000, 0x07ffffff, _soc_nnd_flash_mem_access, nnd);
	csx_mem_mmap(csx, 0x08000000, 0x0bffffff, _soc_nnd_flash_mem_access, nnd);
	csx_mem_mmap(csx, 0x0c000000, 0x0fffffff, _soc_nnd_flash_mem_access, nnd);

	/* **** */

	return(0);
}

uint32_t soc_nnd_flash_read(soc_nnd_p nnd, uint32_t addr, size_t size)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	if(0) LOG("addr = 0x%08x, offset = 0x%08x, size = 0x%08zx",
		addr, offset, size);

	unsigned cs = 0;
	const soc_nnd_unit_p unit = _soc_nnd_flash_unit(nnd, addr, &cs);

	if(0 == unit) {
		LOG("addr = 0x%08x, cs = 0x%08x, offset = 0x%08x, size = 0x%08zx",
			addr, cs, offset, size);

		return(0);
	}

	unsigned cl_index = unit->cl_index;
	unsigned value =  addr & 0xff;

	switch(offset) {
		case RWD:
			switch(unit->cl & 0xff) {
				case 0x70: /* read status */
					value = unit->status;
				break;
				case 0x90: /* read id */
					value = soc_nnd_flash_id[cs][cl_index++];
					unit->cl_index = cl_index < 5 ? cl_index : 0;
				break;
			}
			break;
		case 0x10:
			value = htobe32('DSKI');
			break;
		default:
			LOG("addr = 0x%08x, cs = 0x%08x, value = 0x%08x, size = 0x%08zx, cl = 0x%08x",
				addr, cs, value, size, unit->cl);
			break;
	}

	LOG("addr = 0x%08x, cs = 0x%08x, size = 0x%08zx, cl = 0x%08x:0%08x, value = 0x%08x",
		addr, cs, size, unit->cl, cl_index, value);

	return(value);
}

static void soc_nnd_flash_write_cle(soc_nnd_p nnd, soc_nnd_unit_p unit, size_t size, uint32_t value)
{
	unsigned cs = unit->cs;
	
	LOG("cs = 0x%08x, value = 0x%08x, size = 0x%08zx, cl = 0x%08x", cs, value, size, unit->cl);

	if(0xff == value) { /* reset */
		unit->cl = 0;
		unit->cl_index = 0;
		unit->status = 0;
		BSET(unit->status, 7); /* not write protected */
		BSET(unit->status, 6); /* device ready */
	} else {
		unit->cl <<= 8;
		unit->cl |= (value & 0xff);
		unit->cl_index = 0;
	}

	LOG("cs = 0x%08x, value = 0x%08x, size = 0x%08zx, cl = 0x%08x", cs, value, size, unit->cl);

	UNUSED(nnd);
}

void soc_nnd_flash_write(soc_nnd_p nnd, uint32_t addr, size_t size, uint32_t value)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	unsigned cs = 0;
	const soc_nnd_unit_p unit = _soc_nnd_flash_unit(nnd, addr, &cs);

	if(0 == unit) {
		LOG("addr = 0x%08x, cs = 0x%08x, offset = 0x%08x, size = 0x%08zx, value = 0x%08x",
			addr, cs, offset, size, value);

		return;
	}

	switch(offset) {
		case CLE:
			if(0) LOG("CLE: value = 0x%08x, size = 0x%08zx", value, size);
			soc_nnd_flash_write_cle(nnd, unit, size, value);
			break;
		default:
			LOG("addr = 0x%08x, cs = 0x%08x, offset = 0x%08x, value = 0x%08x, size = 0x%08zx",
				addr, cs, offset, value, size);
			break;
	}
}
