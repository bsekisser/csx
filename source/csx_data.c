#include "config.h"

/* **** */

#include "csx_data.h"

/* **** */

#include "bitfield.h"

/* **** system includes */

#include <endian.h>
#include <stdint.h>

/* **** */

void csx_data_bit_bmas(void* p2dst, csx_data_bit_p sdbp, uint set)
{
	uint value = csx_data_offset_read(p2dst, sdbp->offset, sdbp->size);
	BMAS(value, sdbp->bit, set);

	csx_data_offset_write(p2dst, sdbp->offset, sdbp->size, value);
}

uint csx_data_bit_read(void* p2src, csx_data_bit_p sdbp)
{
	const uint value = csx_data_offset_read(p2src, sdbp->offset, sdbp->size);

	return(BEXT(value, sdbp->bit));
}

#define STRINGIFY(_x) #_x
#define _assert(_test) \
	{ \
		if((_test)) { \
			printf("%s -- size = 0x%08x", STRINGIFY(_test), size); \
			assert((_test)); \
		} \
	}

uint32_t csx_data_read_x(void* p2src, size_t size)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
	_assert((0 <= size) && (8 >= size));
#pragma GCC diagnostic pop

	uint32_t res = 0;
	uint8_t* src = (uint8_t*)p2src;

	for(uint i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

void csx_data_write_x(void* p2dst, size_t size, uint32_t value)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
	_assert((0 <= size) && (8 >= size));
#pragma GCC diagnostic pop

	uint8_t* dst = (uint8_t*)p2dst;

	for(uint i = 0; i < size; i++)
		*dst++ = value >> (i << 3) & 0xff;
}
