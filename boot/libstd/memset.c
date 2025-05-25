#include <data.h>
#include <stddef.h>
#include <string.h>

/* **** */

#pragma GCC optimize("O2")

/* **** */

static inline
void* _memset(void *const p, const unsigned long c, const size_t n)
{
	switch(n) {
		case 16:
			((long long*)p)[0] = c | (((long long)c) << 32);
			((long long*)p)[1] = c | (((long long)c) << 32);
			break;
		case 8:
			((long long*)p)[0] = c | (((long long)c) << 32);
			break;
		case 4: *(long*)p = c; break;
		case 2: *(short*)p = c; break;
		case 1: *(char*)p = c; break;
	}

	return(p + n);
}

extern
void* memset(void *const dst, const int c, const size_t n)
{
	void* p = dst;
	
	if(n >> 2) {
		const unsigned stride_shift = 4;
		const unsigned stride = 1 << stride_shift;
		const unsigned mask = stride - 1;

		unsigned long c32 = c | c << 8;
			c32 |= c32 << 16;

		for(unsigned x = 0; x < (n >> stride_shift); x += stride)
			p = _memset(p, c32, stride);

		for(unsigned x = 0; x < (n >> 2); x++)
			p = _memset(p, c32, 4);
	}

	for(unsigned x = 0; x < (n & 3); x++)
		_memset(p, c, 1);

	return(dst);
}
