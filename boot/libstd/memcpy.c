#include <data.h>
#include <stddef.h>
#include <types.h>

/* **** */

#pragma GGC optimize "Os"

/* **** */

static
void __memcpy(data_ref dst, data_ref src, const size_t bytes)
{
	data_t xxx;

	data_dst(dst, data_src(&xxx, src, bytes), bytes);

	dst->p += bytes;
	src->p += bytes;
}

static
unsigned _memcpy(data_ref dst, data_ref src, const size_t n, const size_t stride_shift)
{
	const unsigned stride = 1 << stride_shift;
	const unsigned mask = stride - 1;
	
	unsigned x = n >> stride_shift;

	while(x--)
		__memcpy(dst, src, stride);

	return(n & mask);
}

/* **** */

extern
void* memcpy(void *const dst, void *const src, const size_t n)
{
	data_t ddst = { .p = dst };
	data_t ssrc = { .p = src };
	
	unsigned count = n;

	count = _memcpy(&ddst, &ssrc, count, 4);
	count = _memcpy(&ddst, &ssrc, count, 3);
	count = _memcpy(&ddst, &ssrc, count, 2);
	count = _memcpy(&ddst, &ssrc, count, 0);

	return(dst);
}
