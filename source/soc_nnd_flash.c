#include "soc_nnd_flash.h"

/* **** */

#include "csx.h"

/* **** */

#include "bitfield.h"
#include "log.h"

/* **** */

typedef struct soc_nnd_t {
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

uint32_t soc_nnd_flash_read(soc_nnd_p nnd, uint32_t addr, uint size)
{
	const uint unit = addr >> 26;
	
	assert(unit < 4);

	uint value = 0;

	if(RWD == (addr & 0x7)) {
		if(0x70 == (nnd->cl & 0xff)) {
			value = nnd->status;
		}
	}
	
	LOG("addr = 0x%08x, unit = 0x%08x, value = 0x%08x, size = 0x%08x, cl = 0x%08x", addr, unit, value, size, nnd->cl);

	return(value);
}

static void soc_nnd_flash_write_cle(soc_nnd_p nnd, uint unit, uint32_t value, uint size)
{
	LOG("unit = 0x%08x, value = 0x%08x, size = 0x%08x, cl = 0x%08x", unit, value, size, nnd->cl);
	
	switch(value) {
		case 0xff: /* reset */
			nnd->cl = 0;
			nnd->status = 0;
			BSET(nnd->status, 7); /* not write protected */
			BSET(nnd->status, 6); /* device ready */
			break;
		default:
			nnd->cl <<= 8;
			nnd->cl |= (value & 0xff);
			break;
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
