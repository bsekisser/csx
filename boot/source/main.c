#include <stdint.h>
#include <string.h>

/* **** */

typedef int (*void_fn)(void);

/* **** */

int main(void)
{
//	strcpy((void*)0x0c000010, "DSKIMG");

	void *const dst = (void*)0x10000000U;
	void *const src = (void*)0x0c000000U + (((4 << 6) + (0 & 63)) << 11);

	(void)memcpy(dst, src, ((1 << 6) << 11));

	void_fn fn = (void*)dst;
	if(0xea000002 == *(uint32_t*)fn)
		fn();
	else {
		void_fn fn = (void*)0x10020000;

		if(0xea000002 == *(uint32_t*)fn)
			fn();
	}
}
