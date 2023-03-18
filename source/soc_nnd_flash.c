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
	uint32_t						cl;
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


const uint8_t soc_nnd_flash_id[5] = {
	0xec, 0xd3, 0x51, 0x95, 0x58
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

static soc_nnd_unit_p _soc_nnd_flash_unit(soc_nnd_p nnd, uint32_t addr)
{
//	const uint cs = addr >> CSx_LSB;
	const uint cs = 0;
	
	const soc_nnd_unit_p unit = &nnd->unit[cs];

	LOG("nnd = 0x%08" PRIxPTR ", addr = 0x%08x, cs = 0x%02x, unit = 0x%08" PRIxPTR,
	    (uintptr_t)nnd, addr, cs, (uintptr_t)unit);

	assert(cs < 16);

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

	const soc_nnd_unit_p unit = _soc_nnd_flash_unit(nnd, addr);

	uint index = (unit->cl & 0x0f);

	uint value = 0;

	switch(offset) {
		case RWD:
			if(0x70 == (unit->cl & 0xff)) { /* read status */
				value = unit->status;
			} else if(0x90 == (unit->cl & 0xf0)) { /* read id */
				value = soc_nnd_flash_id[index++];
				unit->cl = (unit->cl & 0xf0) | ((index < 5) ? index : 0);
			}
			break;
		default:
			LOG("addr = 0x%08x, value = 0x%08x, size = 0x%08zx, cl = 0x%08x",
				addr, value, size, unit->cl);
			break;
	}


	return(value);
}

static void soc_nnd_flash_write_cle(soc_nnd_p nnd, soc_nnd_unit_p unit, size_t size, uint32_t value)
{
	LOG("value = 0x%08x, size = 0x%08zx, cl = 0x%08x", value, size, unit->cl);

	if(0xff == value) { /* reset */
		unit->cl = 0;
		unit->status = 0;
		BSET(unit->status, 7); /* not write protected */
		BSET(unit->status, 6); /* device ready */
	} else {
		unit->cl <<= 8;
		unit->cl |= (value & 0xff);
	}

	LOG("value = 0x%08x, size = 0x%08zx, cl = 0x%08x", value, size, unit->cl);

	UNUSED(nnd);
}

void soc_nnd_flash_write(soc_nnd_p nnd, uint32_t addr, size_t size, uint32_t value)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	const soc_nnd_unit_p unit = _soc_nnd_flash_unit(nnd, addr);

	switch(offset) {
		case CLE:
			LOG("CLE: value = 0x%08x, size = 0x%08zx", value, size);
			soc_nnd_flash_write_cle(nnd, unit, size, value);
			break;
		default:
			LOG("addr = 0x%08x, offset = 0x%08x, value = 0x%08x, size = 0x%08zx",
				addr, offset, value, size);
			break;
	}
}
