#include "csx_nnd_flash.h"

/* **** */

#include "csx.h"

#include "garmin_rgn.h"

/* **** */

#include "libarmvm/include/armvm_mem.h"

#include "libbse/include/action.h"
#include "libbse/include/dump_hex.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/mem_access_le.h"
#include "libbse/include/page.h"

#define kBlockAlloc (1 << kBlockBits)
#define kBlockBits  19
#define kBlockMask (kBlockAlloc - 1)

#define kColumnBits 11
#define kColumnCount (1 << kColumnBits)
#define kColumnMask (kColumnCount - 1)

#define kPageBits 6
#define kPageCount (1 << kPageBits)
#define kPageMask (kPageCount - 1)

#define SIZEOF_ARRAY(_x) (sizeof(_x) / sizeof(_x[0]))

/* **** */

#include <inttypes.h>
#include <stdint.h>
#include <sys/mman.h>

/* **** */

typedef struct dskimg_conf_tag {
	unsigned dump:1;
	unsigned load:1;
	unsigned write:1;
}dskimg_conf_t;

static const dskimg_conf_t dskimg = {
	.dump = 0, .load = 1, .write = 0
};

typedef char page_t[512 << 2];
typedef char page_spare_t[16 << 2];

typedef page_t* page_ptr;
typedef page_ptr const page_ref;

typedef page_ptr* page_hptr;
typedef page_hptr const page_href;

typedef struct block_page_tag {
	page_ptr page;
	page_spare_t spare;

	struct {
		unsigned dirty:1;
	};
}block_page_t;

typedef struct block_page_tag* block_page_ptr;
typedef block_page_ptr const block_page_ref;

typedef block_page_ptr* block_page_hptr;
typedef block_page_hptr const block_page_href;

typedef block_page_t block_t[64];

typedef block_t* block_ptr;
typedef block_ptr const block_ref;

typedef block_ptr* block_hptr;
typedef block_hptr const block_href;

typedef block_ptr device_t[kBlockAlloc];

typedef struct csx_nnd_unit_tag* csx_nnd_unit_ptr;
typedef csx_nnd_unit_ptr const csx_nnd_unit_ref;

typedef struct csx_nnd_unit_tag {
	char data_register[sizeof(page_t) + sizeof(page_spare_t)];
	device_t device;
//
	struct {
		union {
			uint64_t u64;
			unsigned char u8[sizeof(uint64_t)];
		};
		unsigned index;
	}al;

	unsigned cl;
	uint16_t column;
	uint32_t row;
	uint8_t status;
//
	csx_nnd_ptr nnd;
}csx_nnd_unit_t;

typedef struct csx_nnd_tag {
	csx_nnd_unit_t unit[7];
//
	struct {
		page_ptr page;
		block_ptr block;
	}free;
//
	csx_ptr csx;
}csx_nnd_t;

enum {
	RWD = 0x00,
	CLE = 0x02,
	ALE = 0x04,
};

#define kUnitID_LEN 5

static const char csx_nnd_flash_id[7][1 + kUnitID_LEN] = {
//	/* A */ [5] = { 0xec, 0xd3, 0x51, 0x95, 0x58 }, // k9wag08u0a -- 1GBx8
	/* C */ [6] = { 0xec, 0xd3, 0x51, 0x95, 0x58 }, // k9wag08u0a -- 1GBx8
};

/* **** */

static block_ptr csx_nnd_flash_block(csx_nnd_unit_ref unit, const uint32_t block, const unsigned write);
static block_page_ptr csx_nnd_flash_block2blockPage(csx_nnd_unit_ref unit, block_ref p2block, const uint32_t page, const unsigned write);
static block_ptr csx_nnd_flash_block_alloc(csx_nnd_unit_ref unit, block_href h2block);
static void csx_nnd_flash_block_page_erase(block_page_ref block_page);
static void csx_nnd_flash_dskimg_load(csx_nnd_ref nnd, csx_nnd_unit_ref unit);
static void csx_nnd_flash_dskimg_write(csx_nnd_ref nnd, csx_nnd_unit_ref unit);
static uint32_t csx_nnd_flash_mem_access(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write);
static uint32_t csx_nnd_flash_mem_access_x(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write);
static page_ptr csx_nnd_flash_page_alloc(csx_nnd_unit_ref unit, page_href h2page);
static void csx_nnd_flash_page_program(csx_nnd_unit_ref unit, const uint32_t row, const unsigned log);
static char* csx_nnd_flash_page_read(csx_nnd_unit_ref unit, const uint32_t row);
static block_page_ptr csx_nnd_flash_ppa2blockPage(csx_nnd_unit_ref unit, const uint32_t ppa, const unsigned write);
static page_ptr csx_nnd_flash_ppa2page(csx_nnd_unit_ref unit, const uint32_t ppa, const unsigned write);
static uint32_t csx_nnd_flash_read(csx_nnd_ref unit, const uint32_t ppa, const size_t size);
static block_page_ptr csx_nnd_flash_row2blockPage(csx_nnd_unit_ref unit, const uint32_t row, const unsigned write);
static void csx_nnd_flash_write(csx_nnd_ref unit, const uint32_t ppa, const size_t size, const uint32_t *const write);

/* **** */

static
uint64_t _blockPage2row(const unsigned block, const unsigned page)
{ return((block << kPageBits) | page); }

static
uint32_t _ppa2column(const uint32_t ppa)
{ return(ppa & kColumnMask); }

static
uint32_t _ppa2cs(const uint32_t ppa)
{ return((ppa >> 26) & 3); }

static
uint32_t _ppa2offset(const uint32_t ppa)
{ return(ppa & 0x01ffffff); }
//{ return(ppa & 0x03ffffff); }

static
uint32_t _ppa2row(const uint32_t ppa)
{ return(_ppa2offset(ppa) >> kColumnBits); }

static
uint32_t _ppa2unit(const uint32_t ppa)
{ return((ppa >> 25) & 7); }

static
uint32_t _row2block(const uint32_t row)
{ return((row >> kPageBits) & kBlockMask); }

static
uint64_t _row2bpa(const uint64_t row, const uint16_t column)
{ return((row << kColumnBits) | column); }

static
uint8_t _row2page(const uint32_t row)
{ return(row & kPageMask); }

/* **** */

static
int csx_nnd_flash_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	csx_nnd_ref nnd = param;

	/* **** */

	csx_nnd_flash_dskimg_write(nnd, &nnd->unit[6]);

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
int csx_nnd_flash_action_init(int err, void *const param, action_ref)
{
	ACTION_LOG(init);

	csx_nnd_ref nnd = param;
	ERR_NULL(nnd);

	armvm_ref armvm = nnd->csx->armvm;
	ERR_NULL(armvm);

	armvm_mem_ref mem = armvm->mem;
	ERR_NULL(mem);

	/* **** */

	if(dskimg.load)
		csx_nnd_flash_dskimg_load(nnd, &nnd->unit[6]);

	for(unsigned x = 1; x < 7; x++) {
		const uint32_t ppa_start0 = x << 25;
		const uint32_t ppa_end0 = ppa_start0 + 0xfff;

		const unsigned cs = _ppa2cs(ppa_start0);
		const unsigned uunit = _ppa2unit(ppa_start0);

		const uint32_t ppa_start1 = 1 + ppa_end0;
		const uint32_t ppa_end1 = ppa_start0 + ((3 == cs) ? Mb(64) : Mb(32)) - 1;

		const csx_nnd_unit_ref unit = &nnd->unit[uunit];

		if(1) {
			LOG("cs: %u, unit: %u, ppa: 0x%08x(0x%08x)-0x%08x",
				cs, uunit, ppa_start0, ppa_end0, ppa_end1);
		}

		armvm_mem_mmap_cb(mem, ppa_start0, ppa_end0, csx_nnd_flash_mem_access_x, nnd);
		armvm_mem_mmap_cb(mem, ppa_start1, ppa_end1, csx_nnd_flash_mem_access, unit);
	}

	/* **** */

	return(err);
}

action_list_t csx_nnd_flash_action_list = {
	.list = {
		[_ACTION_EXIT] = {{ csx_nnd_flash_action_exit }, { 0 }, 0 },
		[_ACTION_INIT] = {{ csx_nnd_flash_action_init }, { 0 }, 0 },
	}
};

csx_nnd_ptr csx_nnd_flash_alloc(csx_ref csx, csx_nnd_href h2nnd)
{
	ERR_NULL(csx);
	ERR_NULL(h2nnd);

	ACTION_LOG(alloc);

	/* **** */

	csx_nnd_ref nnd = handle_calloc(h2nnd, 1, sizeof(csx_nnd_t));
	ERR_NULL(nnd);

	nnd->csx = csx;

	/* **** */

	for(unsigned x = 0; x < SIZEOF_ARRAY(nnd->unit); x++)
		nnd->unit[x].nnd = nnd;

	/* **** */

	return(nnd);
}

static
block_ptr csx_nnd_flash_block(csx_nnd_unit_ref unit, const uint32_t block, const unsigned write)
{
	block_href h2block = &unit->device[block];
	block_ptr p2block = *h2block;

	if(write && !p2block)
		return(csx_nnd_flash_block_alloc(unit, h2block));

	return(p2block);
}

static
block_page_ptr csx_nnd_flash_block2blockPage(csx_nnd_unit_ref unit, block_ref p2block, const uint32_t page, const unsigned write)
{
	if(0) LOG("page: 0x%02x", page);

	block_page_ref block_page = &(*p2block)[page];

	if(write && !block_page->page) {
		csx_nnd_flash_page_alloc(unit, &block_page->page);
		csx_nnd_flash_block_page_erase(block_page);
	}

	block_page->dirty = write;

	return(block_page);
}

static
block_ptr csx_nnd_flash_block_alloc(csx_nnd_unit_ref unit, block_href h2block)
{
	block_href free_block = &unit->nnd->free.block;
	block_ptr p2block;

	if(*free_block) {
		p2block = *free_block;
		*free_block = **(void***)free_block;
	} else
		p2block = calloc(1, sizeof(block_t));

if(0)	LOG("h2block: 0x%016" PRIxPTR ", p2block: 0x%016" PRIxPTR,
		(uintptr_t)h2block, (uintptr_t)p2block);

	if(h2block) *h2block = p2block;

	if(!p2block) LOG("FAILED");

	return(p2block);
}

static
void csx_nnd_flash_block_erase(csx_nnd_unit_ref unit, const uint32_t row)
{
if(0)	LOG("row: 0x%08x", row);

	for(unsigned page = 0; page < 64; page++) {
		block_page_ref p2blockPage = csx_nnd_flash_row2blockPage(unit, row + page, 0);

		if(p2blockPage)
			csx_nnd_flash_block_page_erase(p2blockPage);
	}
}

static
void csx_nnd_flash_block_page_erase(block_page_ref block_page)
{
	if(block_page) {
		if(block_page->page)
			memset(block_page->page, 255, sizeof(page_t));

		memset(block_page->spare, 0, sizeof(page_spare_t));

		if(1) {
			*(uint16_t*)(&block_page->spare[0 << 4]) = 0xffff;
			*(uint16_t*)(&block_page->spare[1 << 4]) = 0xffff;
			*(uint16_t*)(&block_page->spare[2 << 4]) = 0xffff;
			*(uint16_t*)(&block_page->spare[3 << 4]) = 0xffff;
		}

		block_page->dirty = 1;
	}
}

static
void csx_nnd_flash_dskimg_load(csx_nnd_ref nnd, csx_nnd_unit_ref unit)
{
	int err = 0;

	FILE* fp[3] = {
		fopen(kDSKIMG_CTRL, "r"),
		fopen(kDSKIMG, "r"),
		fopen(kDSKIMG_SPARE, "r")
	};

	if(fp[0] && fp[1] && fp[2]) {
		const char* src = fgets(unit->data_register, 7, fp[0]);
		unit->data_register[7] = 0;

		if(src) {
			const int match = (0 == strncmp("DSKIMG", src, 16));

			if(match) {
				for(;;) {
					uint32_t row = 0;

					size_t count = fread(&row, 4, 1, fp[0]);
					if(!count || feof(fp[0])) break;

					const uint64_t bpa = _row2bpa(row, 0);
if(1)				LOG("bpa: 0x%016" PRIx64 ", row: 0x%08x", bpa, row);

					block_page_ref blockPage = csx_nnd_flash_row2blockPage(unit, row, 1);
					err = !blockPage; if(err) LOG_ACTION(break);
					err = !blockPage->page; if(err) LOG_ACTION(break);

					count = fread(blockPage->page, 1, sizeof(page_t), fp[1]);
					if(!count || feof(fp[0])) break;

					count = fread(blockPage->spare, 1, sizeof(page_spare_t), fp[2]);
					if(!count || feof(fp[0])) break;

					csx_nnd_flash_page_program(unit, row, 0);
				}
			}
		}
	}

	for(unsigned x = 0; x < 3; x++)
		if(fp[x]) fclose(fp[x]);

	if(err) {
		perror("load");
		exit(-1);
	}

	return;
	UNUSED(nnd);
}

static
void csx_nnd_flash_dskimg_write(csx_nnd_ref nnd, csx_nnd_unit_ref unit)
{
	FILE *fp[3] = { 0, 0, 0 };

	if(dskimg.write) {
		fp[0] = fopen(kDSKIMG_CTRL, "w");

		if(0 == fp[0]) {
			perror("open for write failed");
			goto fail_exit;
		}

		fp[1] = fopen(kDSKIMG, "w");

		if(0 == fp[1]) {
			perror("open for write failed");
			goto fail_exit;
		}

		fp[2] = fopen(kDSKIMG_SPARE, "w");

		if(0 == fp[2]) {
			perror("open for write failed");
			goto fail_exit;
		}

		fputs("DSKIMG", fp[0]);
	}

	for(unsigned block = 0; block < kBlockAlloc; block++) {
		block_ref p2block = csx_nnd_flash_block(unit, block, 0);
		if(!p2block) continue;

		for(unsigned page = 0; page < 64; page++) {
			const uint32_t row = _blockPage2row(block, page);
			const uint64_t bpa = _row2bpa(row, 0);

			block_page_ref blockPage = csx_nnd_flash_block2blockPage(unit, p2block, page, 0);
			if(!blockPage->dirty) continue;

if(1)		LOG("block: 0x%08x, page: 0x%02x, bpa: 0x%016" PRIx64 ", row: 0x%08x",
				block, page, bpa, row);

			if(dskimg.write) {
				htole32(row);
				fwrite(&row, 4, 1, fp[0]);

				fwrite(blockPage->page, 1, sizeof(page_t), fp[1]);
				fwrite(blockPage->spare, 1, sizeof(page_spare_t), fp[2]);
			}

			if(dskimg.dump)
				dump_hex(blockPage->page, bpa, sizeof(page_t), 16, 1);
		}
	}

fail_exit:
	for(unsigned x = 0; x < 3; x++)
		if(fp[x]) fclose(fp[x]);

	return;
	UNUSED(nnd);
}

static
uint32_t csx_nnd_flash_mem_access(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	csx_nnd_unit_ref unit = param;

	const uint32_t offset = _ppa2offset(ppa);

	void* p = csx_nnd_flash_ppa2page(unit, ppa, !!write);
	if(p)
		p += _ppa2column(ppa);

	const uint32_t write_data = write ? *write : 0;

	const uint32_t data = p ? mem_access_le(p, size, write) : write_data;

	if(0) {
		const unsigned uunit = _ppa2unit(ppa);
		const unsigned row = _ppa2row(ppa);

		LOG_START("cs: %u, unit: %u(%X), ",
			_ppa2cs(ppa), uunit, uunit << 1);

		if(0)
			_LOG_("data: 0x%08x, write: %u, write_data: 0x%08x, ",
				data, !!write, write_data);

		_LOG_("offset: 0x%08x, ", offset);

		if(0) {
			_LOG_("row: 0x%08x, column: 0x%04x",
				row, _ppa2column(ppa));
			_LOG_(", block: 0x%08x, page: 0x%02x, ",
				_row2block(row), _row2page(row));
		}

		if(write)
			_LOG_("0x%08x => ", data);

		_LOG_("%zu[0x%08x]", size, ppa)

		if(!write) {
			LOG_END(" => 0x%08x", data);
		} else {
			LOG_END();
		}
	}

	return(data);
}

static
uint32_t csx_nnd_flash_mem_access_x(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(write)
		return(csx_nnd_flash_write(param, ppa, size, write), 0);

	return(csx_nnd_flash_read(param, ppa, size));
}

static
page_ptr csx_nnd_flash_page_alloc(csx_nnd_unit_ref unit, page_href h2page)
{
	page_href free_page = &unit->nnd->free.page;
	page_ptr p2page = 0;

	if(*free_page) {
		p2page = *free_page;
		*free_page = **(void***)free_page;
	} else {
#define MMAP_FAILED p2page = 0

		const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
		const int prot = (PROT_READ | PROT_WRITE);

		p2page = mmap(0, sizeof(page_t), prot, flags, -1, 0);
		if(MAP_FAILED == p2page)
			LOG_ACTION(MMAP_FAILED);
	}

if(0)	LOG("h2page: 0x%016" PRIxPTR ", p2page: 0x%016" PRIxPTR,
		(uintptr_t)h2page, (uintptr_t)p2page);

	if(h2page) *h2page = p2page;

	if(!p2page) LOG("FAILED");

	return(p2page);
}

static
void csx_nnd_flash_page_program(csx_nnd_unit_ref unit, const uint32_t row, const unsigned log)
{
	block_page_ref p2blockPage = csx_nnd_flash_row2blockPage(unit, row, 1);

	if(log)
		LOG("row: 0x%08x", row);

	if(p2blockPage) {
		if(!p2blockPage->page)
			csx_nnd_flash_page_alloc(unit, &p2blockPage->page);

		if(p2blockPage->page)
			memcpy(p2blockPage->page, unit->data_register, sizeof(page_t));

		memcpy(p2blockPage->spare, &unit->data_register[sizeof(page_t)], sizeof(p2blockPage->spare));
	} else
		LOG("MISSING BLOCK");
}

static
char* csx_nnd_flash_page_read(csx_nnd_unit_ref unit, const uint32_t row)
{
	block_page_ref p2blockPage = csx_nnd_flash_row2blockPage(unit, row, 0);

if(0)	LOG("row: 0x%08x", row);

	if(p2blockPage) {
		if(p2blockPage->page) {
			memcpy(unit->data_register, p2blockPage->page, sizeof(page_t));
			memcpy(&unit->data_register[sizeof(page_t)], p2blockPage->spare, sizeof(p2blockPage->spare));
		} else {
			void *const spare = &unit->data_register[sizeof(page_t)];

			memset(unit->data_register, 255, sizeof(page_t));
			memset(spare, 0, sizeof(page_spare_t));

			if(1) {
				*(uint16_t*)(spare + (0 << 4)) = 0xffff;
				*(uint16_t*)(spare + (1 << 4)) = 0xffff;
				*(uint16_t*)(spare + (2 << 4)) = 0xffff;
				*(uint16_t*)(spare + (3 << 4)) = 0xffff;
			}
		}

		return(unit->data_register);
	}

	return(0);
}

static
block_page_ptr csx_nnd_flash_ppa2blockPage(csx_nnd_unit_ref unit, const uint32_t ppa, const unsigned write)
{
	if(0) LOG("ppa: 0x%08x, row: 0x%08x", ppa, _ppa2row(ppa));

	return(csx_nnd_flash_row2blockPage(unit, _ppa2row(ppa), write));
}

static
page_ptr csx_nnd_flash_ppa2page(csx_nnd_unit_ref unit, const uint32_t ppa, const unsigned write)
{
	block_page_ref block_page = csx_nnd_flash_ppa2blockPage(unit, ppa, write);

	return(block_page ? block_page->page : 0);
}

static
uint8_t csx_nnd_flash_read_rwd(csx_nnd_unit_ref unit, const uint32_t ppa)
{
	const uint16_t column = unit->column;
	uint8_t data = 0;
	const unsigned uunit = _ppa2unit(ppa);

	switch(unit->cl & 255) {
		case 0x70: // status
			data = unit->status;
			break;
		case 0x90: // id
			if(column < kUnitID_LEN)
				data = csx_nnd_flash_id[uunit][unit->column++];
			break;
		case 0x00: // ??
		case 0x30: // data read
		case 0xe0: // random data output
			if(column < sizeof(unit->data_register))
				data = unit->data_register[unit->column++];
			break;
		default:
			LOG("cs: %u, unit: %u(%X), row: 0x%08x, column: 0x%08x, al: 0x%016" PRIx64 ", cl: 0x%08x",
					_ppa2cs(ppa), uunit, uunit << 1, unit->row, column,
						unit->al.u64, unit->cl);
			LOG_ACTION(exit(-1));
			break;
	}

	if(0) {
		LOG("cs: %u, unit: %u(%X), row: 0x%08x, column: 0x%08x, al: 0x%016" PRIx64 ", cl: 0x%08x, data: 0x%02x",
			_ppa2cs(ppa), uunit, uunit << 1, unit->row, column,
				unit->al.u64, unit->cl, data);
	}

	return(data);
}

static
uint32_t csx_nnd_flash_read(csx_nnd_ref nnd, const uint32_t ppa, const size_t size)
{
	const uint32_t offset = _ppa2offset(ppa);
	csx_nnd_unit_ref unit = &nnd->unit[_ppa2unit(ppa)];

	if(RWD == offset)
		return(csx_nnd_flash_read_rwd(unit, ppa));

	const uint32_t data = csx_nnd_flash_mem_access(unit, offset, size, 0);

	if(0) {
		const unsigned uunit = _ppa2unit(ppa);

		LOG_START("cs: %u, unit: %u(%X), cl: 0x%08x, ",
			_ppa2cs(ppa), uunit, uunit << 1, unit->cl);
		LOG_END("%zu[0x%08x] => 0x%08x", size, ppa, data);
	}

	return(data);
}

static
block_ptr csx_nnd_flash_row2block(csx_nnd_unit_ref unit, const uint32_t row, const unsigned write)
{ return(csx_nnd_flash_block(unit, _row2block(row), write)); }

static
block_page_ptr csx_nnd_flash_row2blockPage(csx_nnd_unit_ref unit, const uint32_t row, const unsigned write)
{
	block_ref p2block = csx_nnd_flash_row2block(unit, row, write);
	if(!p2block) return(0);

	return(csx_nnd_flash_block2blockPage(unit, p2block, _row2page(row), write));
}

#if 0
static
page_ptr csx_nnd_flash_row2page(csx_nnd_unit_ref unit, const uint32_t row, const unsigned write)
{
	block_page_ref block_page = csx_nnd_flash_row2blockPage(unit, row, write);

	return(block_page ? block_page->page : 0);
}
#endif

static
void csx_nnd_flash_write_ale(csx_nnd_unit_ref unit, const uint32_t ppa, const uint8_t value)
{
	if(unit->al.index < sizeof(unit->al.u8))
		unit->al.u8[++unit->al.index] = value;

	switch(unit->cl & 255) {
		case 0x00: // setup for read
		case 0x05: // setup for random data read
		case 0x60: // setup for block erase
		case 0x80: // setup for page program
			break;
		case 0x90: // setup for id
			unit->column = unit->al.u8[0];
			break;
		default: {
			const unsigned uunit = _ppa2unit(ppa);

			LOG("cs: %u, unit: %u(%X), cl: 0x%08x, 0x%016" PRIx64 " <-- 0x%02x",
				_ppa2cs(ppa), uunit, uunit << 1, unit->cl,
					unit->al.u64, value);
		}	break;
	}
}

static
void csx_nnd_flash_write_cle(csx_nnd_unit_ref unit, const uint32_t ppa, const uint8_t value)
{
	const uint32_t cl = unit->cl;
	unit->cl = (unit->cl << 8) | value;

	switch(value) {
		case 0x00: // setup for read
		case 0x05: // setup for random data read
		case 0x60: // setup for block erase
			unit->al.index = 0;
			unit->al.u64 = 0;
			break;
		case 0x80: // setup for page program
			unit->al.index = 0;
			unit->al.u64 = 0;
			unit->column = 0;
			break;
		case 0xff: // reset
			unit->al.index = 0;
			unit->al.u64 = 0;
			unit->cl = 0;
			unit->column = 0;
			unit->row = 0;
			unit->status = (1 << 7) | (1 << 6);
			break;
		default: switch(value) {
			case 0x10: break; // page program
			case 0x30: break; // read
			case 0x70: break; // status
			case 0x90: break; // id
			case 0xd0: break; // block erase
			case 0xe0: break; // random data read
			default: {
				const unsigned uunit = _ppa2unit(ppa);

				LOG("cs: %u, unit: %u(%X), 0x%08x <-- 0x%02x",
					_ppa2cs(ppa), uunit, uunit << 1, cl, value);
			}	break;
		}	break;
	}

	void* al = &unit->al.u8;

	switch(unit->cl & 0xffff) {
		case 0x0030: // data read
		case 0x05e0: // random data read
		case 0x8010: // page program
			unit->column = le16toh(*(uint16_t*)al++) & 0xfff;
			break;
		case 0x60d0: // block erase
			unit->row = le32toh(*(uint32_t*)al++);
			break;
	}

	switch(unit->cl & 0xffff) {
		case 0x0030: // data read
		case 0x8010: // page program
			unit->row = le32toh(*(uint32_t*)al++);
			break;
	}

	switch(unit->cl & 0xffff) {
		case 0x0030: // page read
			csx_nnd_flash_page_read(unit, unit->row);
			break;
		case 0x60d0: // block erase
			csx_nnd_flash_block_erase(unit, unit->row);
			break;
		case 0x8010: // page program
			csx_nnd_flash_page_program(unit, unit->row, 1);
			break;
	}
}

static
void csx_nnd_flash_write_rwd(csx_nnd_unit_ref unit, const uint32_t ppa, const uint8_t value)
{
	if(0) {
		const unsigned uunit = _ppa2unit(ppa);

		LOG_START();
			_LOG_("cs: %u, unit: %u(%X)", _ppa2cs(ppa), uunit, uunit << 1);
			_LOG_(", al: 0x%016" PRIx64 ", cl: 0x%08x", unit->al.u64, unit->cl);
			_LOG_(", row: 0x%08x, column: 0x%08x", unit->row, unit->column);
			_LOG_(", data: 0x%02x", value);
		LOG_END();
	}

	if(unit->column < sizeof(unit->data_register))
		unit->data_register[unit->column++] = value;
}

static
void csx_nnd_flash_write(csx_nnd_ref nnd, const uint32_t ppa, const size_t size, const uint32_t *const write)
{
	assert(1 == size);

	const uint32_t offset = _ppa2offset(ppa);
	csx_nnd_unit_ref unit = &nnd->unit[_ppa2unit(ppa)];

	switch(offset) {
		case ALE:
			assert(1 == size);
			return(csx_nnd_flash_write_ale(unit, ppa, *write));
		case CLE:
			assert(1 == size);
			return(csx_nnd_flash_write_cle(unit, ppa, *write));
		case RWD:
			assert(1 == size);
			return(csx_nnd_flash_write_rwd(unit, ppa, *write));
		default: {
			const unsigned uunit = _ppa2unit(ppa);

			LOG_START("cs: %u, unit: %u(%X), cl: 0x%08x, ",
				_ppa2cs(ppa), uunit, uunit << 1, unit->cl);
			LOG_END("0x%08x => %zu[0x%08x]", *write, size, ppa);
		}	return((void)csx_nnd_flash_mem_access(unit, ppa, size, (void*)write));
	}
}
