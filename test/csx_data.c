#define uint unsigned int

#include <stdint.h>

uint32_t _csx_data_read_x(void* p2src, uint8_t size)
{
	uint32_t res = 0;
	uint8_t* src = (uint8_t*)p2src;

	size <<= 3;
	for(int i = 0; i < size; i += 8)
		res |= ((*src++) << i);

	return(res);
}

uint32_t _csx_data_read_u(void* p2src, uint8_t size)
{
	uint32_t res = 0;
	uint8_t* src = (uint8_t*)p2src;

	size <<= 3;
	for(uint i = 0; i < size; i += 8)
		res |= ((*src++) << i);

	return(res);
}

uint32_t _csx_data_read_udc(void* p2src, uint8_t size)
{
	uint32_t res = 0;
	uint8_t* src = (uint8_t*)p2src;

	uint index = 0;
	for(uint i = size; i != 0; i--)
		res |= *src << index, src++, index += 8;

	return(res);
}

uint32_t _csx_data_read_udc_b(void* p2src, uint8_t size)
{
	uint32_t res = 0;
	uint8_t* src = (uint8_t*)p2src;

	uint index = 0;
	for(uint i = size; i != 0; i--) {
		uint tmp = (*src++) << index;
		res |= tmp;
		index += 8;
	}

	return(res);
}

void _csx_data_write_x(void* p2dst, uint32_t value, uint8_t size)
{
	uint8_t* dst = (uint8_t*)p2dst;

	size <<= 3;
	for(int i = 0; i < size; i += 8)
		*dst++ = (value >> i) & 0xff;
}

void _csx_data_write_udc(void* p2dst, uint32_t value, uint8_t size)
{
	uint8_t* dst = (uint8_t*)p2dst;

	for(uint i = size; i != 0; i--)
		*dst = value, dst++, value >>= 8;
}

void _csx_data_write_udc_b(void* p2dst, uint32_t value, uint8_t size)
{
	uint8_t* dst = (uint8_t*)p2dst;

	for(uint i = size; i != 0U; i--)
		(*dst++) = (value >> ((size - i) << 3)) & 0xff;
}

void _csx_data_write_udc_c(void* p2dst, uint32_t value, uint8_t size)
{
	uint8_t* dst = (uint8_t*)p2dst;

	if(size) {
		do {
			*dst = value & 0xff, dst++,	value >>= 8;
		}while(size--);
	}
}
