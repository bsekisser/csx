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

typedef struct soc_nnd_t {
	csx_p							csx;

	uint32_t						cl;
	uint32_t						status;
}soc_nnd_t;

/* **** */

enum {
	RWD = 0x00,
	CLE = 0x02,
	ALE = 0x04,
};

/* **** */

int soc_nnd_flash_init(csx_p csx, soc_nnd_h h2nnd)
{
	soc_nnd_p nnd = calloc(1, sizeof(soc_nnd_t));
	ERR_NULL(nnd);

	/* **** */

	/* **** */

	*h2nnd = nnd;

	return(0);
}

const uint16_t soc_nnd_flash_id = 0x79ec; /* samsung */
//const uint16_t soc_nnd_flash_id = 0x7998; /* toshiba */
//const uint16_t soc_nnd_flash_id = 0x7904; /* fujitsu */

uint32_t soc_nnd_flash_read(soc_nnd_p nnd, uint32_t addr, uint size)
{
	const uint unit = addr >> 26;
	
	assert(unit < 4);

	uint index = (nnd->cl & 0x0f);

	uint value = 0;

	if(RWD == (addr & 0x7)) {
		if(0x70 == (nnd->cl & 0xff)) { /* read status */
			value = nnd->status;
		} else if(0x90 == (nnd->cl & 0xf0)) { /* read id */
			value = (soc_nnd_flash_id >> (index << 3)) & 0xff;
			nnd->cl = (nnd->cl & 0xf0) | (index + 1);
		}
	}
	
	LOG("addr = 0x%08x, unit = 0x%08x, value = 0x%08x, size = 0x%08x, cl = 0x%08x", addr, unit, value, size, nnd->cl);

	return(value);
}

static void soc_nnd_flash_write_cle(soc_nnd_p nnd, uint unit, uint32_t value, uint size)
{
	LOG("unit = 0x%08x, value = 0x%08x, size = 0x%08x, cl = 0x%08x", unit, value, size, nnd->cl);
	
	if(0xff == value) { /* reset */
		nnd->cl = 0;
		nnd->status = 0;
		BSET(nnd->status, 7); /* not write protected */
		BSET(nnd->status, 6); /* device ready */
	} else {
		nnd->cl <<= 8;
		nnd->cl |= (value & 0xff);
	}

	LOG("unit = 0x%08x, value = 0x%08x, size = 0x%08x, cl = 0x%08x", unit, value, size, nnd->cl);
}

void soc_nnd_flash_write(soc_nnd_p nnd, uint32_t addr, uint32_t value, uint size)
{
	const uint unit = addr >> 26;
	
	assert(unit < 4);
	
	const uint32_t offset = addr & 0x07;
	
	switch(offset) {
		case CLE:
			soc_nnd_flash_write_cle(nnd, unit, value, size);
			break;
	}
}
