#include "csx_nnd_flash.h"

/* **** */

#include "csx.h"

/* **** */

#include "libarmvm/include/armvm_mem.h"

#include "libbse/include/bitfield.h"
#include "libbse/include/dump_hex.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/mem_access_le.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef char page_t[2112];
typedef page_t* page_p;
typedef page_p* page_h;
typedef page_p block_t[64];
typedef page_p* block_p;
typedef page_p** block_h;
typedef block_p device_t[2048];

typedef struct csx_nnd_unit_t* csx_nnd_unit_p;
typedef struct csx_nnd_unit_t {
	page_t							data_register;
	device_t						device;
//	page_p							page_register;

	uint16_t						column; // byte in page
	uint32_t						row; // block & page

	unsigned						al;
	unsigned						al_count;

	uint32_t						cl;
	unsigned						cs;
	uint32_t						status;
//
	csx_p							csx;
	csx_nnd_p						nnd;
}csx_nnd_unit_t;

typedef struct csx_nnd_t {
	csx_nnd_unit_t					unit[16];

	csx_p							csx;

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}csx_nnd_t;

/* **** */

enum {
	RWD = 0x00,
	CLE = 0x02,
	ALE = 0x04,
};

#if 0
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
#endif

#define CSx_LSB 24
#define OFFSET_MSB (CSx_LSB - 1)

const uint8_t csx_nnd_flash_id[16][8] = {
//	[0xc] = { 0xec, 0x76, 0x51, 0x95, 0x58 }, // ???
	[0xc] = { 0xec, 0xd3, 0x51, 0x95, 0x58 }, // k9wag08u0a -- 1GBx8
};

/* **** */

static page_p __csx_nnd_flash_p2page(csx_nnd_p const nnd, csx_nnd_unit_p const unit,
	const uint32_t row, uint32_t *const write);

static int __csx_nnd_flash_atexit(void* param)
{
	if(_trace_atexit) {
		LOG(">>");
	}

	const csx_nnd_p nnd = (csx_nnd_p)*(void**)param;
	const csx_nnd_unit_p unit = &nnd->unit[12];

if(1) for(unsigned block = 0; block < 2048; block++) {
		for(unsigned page = 0; page < 64; page++) {
			const uint32_t bpa = block << 6 | page;
			const uint32_t ppa = bpa << 11;

			page_p p = __csx_nnd_flash_p2page(nnd, unit, bpa, 0);

			if(p) {
if(0)			LOG("ppa: 0x%08x, block: 0x%06x, page: 0x%02x, 0x%016" PRIxPTR,
					ppa, block, page, (uintptr_t)p);

				dump_hex((void*)p, ppa, sizeof(page_t), 24, 1);
			}
		}
	}

	handle_free(param);

	if(_trace_atexit_pedantic) {
		LOG("<<");
	}

	return(0);
}

static block_h __csx_nnd_flash_h2block(csx_nnd_p const nnd, csx_nnd_unit_p const unit,
	const uint32_t row)
{
	const uint32_t block = (row & 0xffffc0) >> 6;

	assert(block < sizeof(unit->device) / sizeof(unit->device[0]));

	return(&unit->device[block]);
	UNUSED(nnd);
}

static page_p __csx_nnd_flash_p2page(csx_nnd_p const nnd, csx_nnd_unit_p const unit,
	const uint32_t row, uint32_t *const write)
{
	const unsigned block = (row & 0xffffc0) >> 6;
	const unsigned page = row & 0x3f;

	const block_h h2block = __csx_nnd_flash_h2block(nnd, unit, row);

	if(write) {
		if(!h2block[0]) {
			*h2block = calloc(1, sizeof(block_t));

if(0)		LOG("row: 0x%08x, block: 0x%06x, 0x%016" PRIxPTR ", 0x%016" PRIxPTR,
				row, block, (uintptr_t)h2block, (uintptr_t)*h2block);
		}
	}

	const block_p p2block = h2block[0];
	const page_h h2page = p2block ? &p2block[page] : 0;

	if(write) {
		if(!h2page[0]) {
			*h2page = calloc(1, sizeof(page_t));

if(0)		LOG("row: 0x%08x, block: 0x%06x, page: 0x%02x, 0x%016" PRIxPTR,
				row, block, page, (uintptr_t)*h2page);
		}
	}

	const page_p p2page = h2page ? *h2page : 0;

	return(p2page);
}

static void _csx_nnd_flash_block_erase(csx_nnd_p const nnd, csx_nnd_unit_p const unit,
	const uint32_t ppa)
{
	for(unsigned pages = 64; pages; pages--) {
		page_p p = __csx_nnd_flash_p2page(nnd, unit, ppa + pages - 1, 0);

		if(p)
			memset(p, 0, sizeof(page_t));
	}
}

static uint32_t _csx_nnd_flash_rwd(csx_nnd_p const nnd, csx_nnd_unit_p const unit,
	const uint32_t row, const uint16_t column, const size_t size, uint32_t *const write);

static void _csx_nnd_flash_page_program(csx_nnd_p const nnd, csx_nnd_unit_p const unit,
	const uint32_t ppa)
{
	assert(nnd);
	assert(unit);

	const uint32_t block = ppa >> 6;
	const uint32_t page = ppa & 0x3f;

	page_p p = __csx_nnd_flash_p2page(nnd, unit, ppa, (void*)0xfeedface);
	assert(p);

if(0) 	LOG("ppa: 0x%08x, block: 0x%06x, page: 0x%03x, 0x%016" PRIxPTR ", 0x%016" PRIxPTR ,
			ppa, block, page, (uintptr_t)p, (uintptr_t)unit->data_register);

	if(p)
		memcpy(p, unit->data_register, sizeof(page_t));
}

static uint32_t _csx_nnd_flash_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write) {
	if(write)
		csx_nnd_flash_write(param, ppa, size, *write);
	else
		return(csx_nnd_flash_read(param, ppa, size));

	return(0);
}

static uint32_t _csx_nnd_flash_rwd(csx_nnd_p const nnd, csx_nnd_unit_p const unit,
	const uint32_t row, const uint16_t column, const size_t size, uint32_t *const write)
{
	assert(column < sizeof(page_t));

	page_p page = __csx_nnd_flash_p2page(nnd, unit, row, write);

	if(page)
		return(mem_access_le(&page[column], size, write));

	return(0);
}

static uint32_t _csx_nnd_flash_rwd_ppa(csx_nnd_p const nnd, csx_nnd_unit_p const unit,
	const uint32_t ppa, const size_t size, uint32_t *const write)
{
	const uint16_t column = ppa & 0x7ff;
	const uint32_t row = (ppa >> 11) & 0x7fffff;

	return(_csx_nnd_flash_rwd(nnd, unit, row, column, size, write));
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
	if(0) {
		device_t device;
		LOG("sizeof device_t: 0x%08zx(0x%08zx) -- blocks: 0x%08zx",
			sizeof(device_t), sizeof(device[0]), sizeof(device_t) / sizeof(device[0]));

		block_t block;
		LOG("sizeof block_t: 0x%08zx(0x%08zx) -- pages: 0x%08zx",
			sizeof(block_t), sizeof(block[0]), sizeof(block_t) / sizeof(block[0]));

		LOG("sizeof page_t: 0x%08zx", sizeof(page_t));
	}

	ERR_NULL(nnd);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_p csx = nnd->csx;
	armvm_mem_p mem = csx->armvm->mem;

	armvm_mem_mmap(mem, 0x02000000, 0x03ffffff, _csx_nnd_flash_mem_access, nnd);
	armvm_mem_mmap(mem, 0x04000000, 0x07ffffff, _csx_nnd_flash_mem_access, nnd);
	armvm_mem_mmap(mem, 0x08000000, 0x0bffffff, _csx_nnd_flash_mem_access, nnd);
	armvm_mem_mmap(mem, 0x0c000000, 0x0fffffff, _csx_nnd_flash_mem_access, nnd);

	/* **** */
}

static uint32_t csx_nnd_flash_read_rwd(csx_nnd_p const nnd, csx_nnd_unit_p const unit, const uint32_t addr, const size_t size)
{
	const uint32_t column = unit->column;

	switch(unit->cl & 0xff) {
		case 0x70: /* read status */
			return(unit->status);
		case 0x90: /* read id */
			if(unit->column < sizeof(csx_nnd_flash_id)) {
				unit->column += size;
				return(mem_access_le((void *const)&csx_nnd_flash_id[unit->cs][column], size, 0));
			}
		break;
		default:
			switch(unit->cl & 0xffff) {
				case 0x05e0: // random data output
				case 0x0030: // read
					if(unit->column < sizeof(page_t)) {
						unit->column += size;
						return(_csx_nnd_flash_rwd(nnd, unit, unit->row, column, size, 0));
					}
				break;
				default:
					if(1) {
						if(unit->column < sizeof(page_t)) {
							unit->column += size;
							return(mem_access_le(&unit->data_register[column], size, 0));
						}
					} else {
						LOG("addr = 0x%08x, cs = 0x%02x, size = 0x%02zx, cl = 0x%08x",
							addr, unit->cs, size, unit->cl);
						LOG_ACTION(exit(-1));
					}
				break;
			};
		break;
	}

	return(0);
}

uint32_t csx_nnd_flash_read(csx_nnd_p nnd, uint32_t addr, size_t size)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	if(0) LOG("addr = 0x%08x, offset = 0x%08x, size = 0x%02zx",
		addr, offset, size);

	unsigned cs = 0;
	const csx_nnd_unit_p unit = _csx_nnd_flash_unit(nnd, addr, &cs);

	if(0 == unit) {
		LOG("addr = 0x%08x, cs = 0x%02x, offset = 0x%08x, size = 0x%02zx",
			addr, cs, offset, size);

		return(0);
	}

	switch(offset) {
		case ALE:
		case CLE:
			LOG_ACTION(exit(-1));
			break;
		case RWD:
			return(csx_nnd_flash_read_rwd(nnd, unit, addr, size));
		default:
			return(_csx_nnd_flash_rwd_ppa(nnd, unit, addr, size, 0));
	}

	return(0);
}

static void csx_nnd_flash_write_ale(csx_nnd_p nnd, csx_nnd_unit_p unit, size_t size, uint32_t value)
{
	assert(1 == size);

	if((1 + unit->al) > unit->al_count)
		return;

	switch(unit->al) {
		case 0:
			unit->column = value;
			break;
		case 1:
			unit->column |= ((value & 15) << 8);
			break;
		case 2:
			unit->row = value;
			break;
		case 3:
			unit->row |= (value << 8);
			break;
		case 4:
			unit->row |= ((value & 7) << 16);
			break;
		default: // ignore;
			return;
	}

	unit->al++;

	if(0) LOG("value = 0x%08x, row = 0x%06x, column = 0x%03x", value, unit->row, unit->column);
	UNUSED(nnd);
}

static void csx_nnd_flash_write_cle(csx_nnd_p nnd, csx_nnd_unit_p unit, size_t size, uint32_t value)
{
	assert(1 == size);

	unsigned cs = unit->cs;

	if(0) LOG("cs = 0x%02x, value = 0x%08x, size = 0x%02zx, cl = 0x%08x", cs, value, size, unit->cl);

	if(0xff == value) { /* reset */
		unit->al = 0;
		unit->al_count = 0;
		unit->cl = 0;
		unit->column = 0;
		unit->row = 0;
		unit->status = 0;
		BSET(unit->status, 7); /* not write protected */
		BSET(unit->status, 6); /* device ready */
	} else {
		unit->cl <<= 8;
		unit->cl |= (value & 0xff);

		switch(value) {
			case 0x00: // setup read
			case 0x80: // setup page program
				unit->al=0;
				unit->al_count = 5;
				break;
			case 0x05: // random data output
//			case 0x85: // copy-back program
				unit->al = 0;
				unit->al_count = 2;
				break;
			case 0x60: // setup block erase
				unit->al = 2;
				unit->al_count = 3;
				break;
			case 0x70: // read status
				break;
			case 0x90: // read id
				unit->al = 0;
				unit->al_count = 1;
				break;
			default:
				switch(unit->cl & 0xffff) {
					case 0x0030: // read
					case 0x05e0: // random data output
						break;
					case 0x60d0: // block erase
						_csx_nnd_flash_block_erase(nnd, unit, unit->row);
						break;
					case 0x8010: // page program
						_csx_nnd_flash_page_program(nnd, unit, unit->row);
						break;
					default:
if(1) 					LOG("cs = 0x%02x, value = 0x%08x, size = 0x%02zx, cl = 0x%08x, row = 0x%04x, column = %04x",
							cs, value, size, unit->cl, unit->row, unit->column);
						LOG_ACTION(exit(-1));
				}
				break;
		}
	}

	if(0) LOG("cs = 0x%02x, value = 0x%08x, size = 0x%02zx, cl = 0x%08x, row = 0x%04x, column = %04x",
		cs, value, size, unit->cl, unit->row, unit->column);

	UNUSED(nnd);
}

static void csx_nnd_flash_write_rwd(csx_nnd_p nnd, csx_nnd_unit_p unit, size_t size, uint32_t value)
{
	assert(nnd);
	assert(unit);
	assert(1 == size);

	const uint32_t column = unit->column;
	switch(unit->cl & 0xff) {
		case 0x80:
		case 0x85:
			if(unit->column < sizeof(page_t)) {
				unit->column += size;
				mem_access_le(&unit->data_register[column], size, &value);
			}
			break;
		default:
		switch(unit->cl & 0xffff) {
			default:
				LOG("cl = 0x%08x, cs = 0x%02x, value = 0x%08x, size = 0x%02zx",
					unit->cl, unit->cs, value, size);
				LOG_ACTION(exit(-1));
		}
		break;
	}

	UNUSED(nnd);
}

void csx_nnd_flash_write(csx_nnd_p nnd, uint32_t addr, size_t size, uint32_t value)
{
	const uint32_t offset = mlBFEXT(addr, OFFSET_MSB, 0);

	unsigned cs = 0;
	const csx_nnd_unit_p unit = _csx_nnd_flash_unit(nnd, addr, &cs);

	if(0 == unit) {
		LOG("addr = 0x%08x, cs = 0x%02x, offset = 0x%08x, size = 0x%02zx, value = 0x%08x",
			addr, cs, offset, size, value);

		return;
	}

	switch(offset) {
		case ALE:
			if(0) LOG("ALE: cl = 0x%08x, value = 0x%08x, size = 0x%02zx, row = 0x%06x, column = 0x%03x",
				unit->cl, value, size, unit->row, unit->column);
			return(csx_nnd_flash_write_ale(nnd, unit, size, value));
		case CLE:
			if(0) LOG("CLE: value = 0x%08x, size = 0x%02zx", value, size);
			return(csx_nnd_flash_write_cle(nnd, unit, size, value));
		case RWD:
			if(0) LOG("RWD: cl = 0x%08x, value = 0x%08x, size = 0x%02zx, row = 0x%06x, column = 0x%03x",
				unit->cl, value, size, unit->row, unit->column);
			return(csx_nnd_flash_write_rwd(nnd, unit, size, value));
			break;
		default:
			LOG("addr = 0x%08x, cs = 0x%02x, offset = 0x%08x, value = 0x%08x, size = 0x%02zx",
				addr, cs, offset, value, size);
			LOG_ACTION(exit(-1));
			break;
	}
}
