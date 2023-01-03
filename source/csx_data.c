#include "csx_data.h"

/* **** */

#include "bitfield.h"

/* **** */

void csx_data_bit_bmas(void* p2dst, csx_data_bit_p sdbp, uint set)
{
	const void* p2data = p2dst + sdbp->offset;

	uint value = csx_data_bit_read((void*)p2data, sdbp);
	BMAS(value, sdbp->bit, set);

	csx_data_write((void*)p2data, value, sdbp->size);
}

uint csx_data_bit_read(void* p2src, csx_data_bit_p sdbp)
{
	const void* p2data = p2src + sdbp->offset;

	const uint value = csx_data_read((void*)p2data, sdbp->size);

	return(BEXT(value, sdbp->bit));
}

uint32_t csx_data_read_x(void* p2src, uint8_t size)
{
	uint32_t res = 0;

	uint8_t* src = (uint8_t*)p2src;

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

void csx_data_write_x(void* p2dst, uint32_t value, uint8_t size)
{
	uint8_t* dst = (uint8_t*)p2dst;

	for(int i = 0; i < size; i++)
		*dst++ = value >> (i << 3) & 0xff;
}
