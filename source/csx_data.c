#include "config.h"

/* **** */

#include "csx_data.h"

/* **** */

#include "libbse/include/bitfield.h"

/* **** system includes */

#include <endian.h>
#include <stdint.h>

/* **** */

void csx_data_bit_bmas(void *const p2dst, csx_data_bit_ref sdbp, const unsigned set)
{
	unsigned value = csx_data_offset_read(p2dst, sdbp->offset, sdbp->size);
	BMAS(value, sdbp->bit, set);

	csx_data_offset_write(p2dst, sdbp->offset, sdbp->size, value);
}

unsigned csx_data_bit_read(void *const p2src, csx_data_bit_ref sdbp)
{
	const unsigned value = csx_data_offset_read(p2src, sdbp->offset, sdbp->size);

	return(BEXT(value, sdbp->bit));
}

#define STRINGIFY(_x) #_x
#define _assert(_test) \
	{ \
		if((_test)) { \
			printf("%s -- size = 0x%08zx", STRINGIFY(_test), size); \
			assert((_test)); \
		} \
	}
