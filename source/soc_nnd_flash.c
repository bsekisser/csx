#include "soc_nnd_flash.h"

/* **** */

#include "csx.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
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

static soc_nnd_unit_p _soc_nnd_flash_unit(soc_nnd_p nnd, uint32_t addr)
{
//	const uint cs = addr >> CSx_LSB;
	const uint cs = 0;
	
	const soc_nnd_unit_p unit = &nnd->unit[cs];

	LOG("nnd = 0x%08x, addr = 0x%08x, cs = 0x%02x, unit = 0x%08x", (uint)nnd, addr, cs, (uint)unit);

	assert(cs < 16);

	return(unit);
}

/* **** */

int soc_nnd_flash_init(csx_p csx, soc_nnd_h h2nnd)
{
	soc_nnd_p nnd = calloc(1, sizeof(soc_nnd_t));
	ERR_NULL(nnd);

	nnd->csx = csx;

	/* **** */

	/* **** */

	*h2nnd = nnd;

	return(0);
}

uint32_t soc_nnd_flash_read(soc_nnd_p nnd, uint32_t addr, uint size)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	if(0) LOG("addr = 0x%08x, offset = 0x%08x, size = 0x%08x",
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
			LOG("addr = 0x%08x, value = 0x%08x, size = 0x%08x, cl = 0x%08x",
				addr, value, size, unit->cl);
			break;
	}


	return(value);
}

static void soc_nnd_flash_write_cle(soc_nnd_p nnd, soc_nnd_unit_p unit, uint32_t value, uint size)
{
	LOG("value = 0x%08x, size = 0x%08x, cl = 0x%08x", value, size, unit->cl);

	if(0xff == value) { /* reset */
		unit->cl = 0;
		unit->status = 0;
		BSET(unit->status, 7); /* not write protected */
		BSET(unit->status, 6); /* device ready */
	} else {
		unit->cl <<= 8;
		unit->cl |= (value & 0xff);
	}

	LOG("value = 0x%08x, size = 0x%08x, cl = 0x%08x", value, size, unit->cl);

	UNUSED(nnd);
}

void soc_nnd_flash_write(soc_nnd_p nnd, uint32_t addr, uint32_t value, uint size)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	const soc_nnd_unit_p unit = _soc_nnd_flash_unit(nnd, addr);

	switch(offset) {
		case CLE:
			LOG("CLE: value = 0x%08x, size = 0x%08x", value, size);
			soc_nnd_flash_write_cle(nnd, unit, value, size);
			break;
		default:
			LOG("addr = 0x%08x, offset = 0x%08x, value = 0x%08x, size = 0x%08x",
				addr, offset, value, size);
			break;
	}
}
