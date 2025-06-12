#include <stdint.h>
#include <string.h>

/* **** */

typedef void (*void_fn)(int, int, int, int);

/* **** */

static __attribute__((naked))
void _bleep_fn(void_fn fn)
{
	register unsigned* r0 asm("r0") = 0;
	
	asm(
		"mov r11, sp;"
		"mov r10, r0;"
		"mov r9, r0;"
		"mov r8, r0;"
		"mov r7, r0;"
		"mov r6, r0;"
		"mov r5, r0;"
		"mov r4, r0;"
		: /* no output */
	/* input */
		: "r"(r0)
	/* clobbers */
		: "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"
		);

	fn(0, 0, 0, 0);
}

static
int _bleep_test(uint32_t* p)
{ return(0xea000002U == *p); }

/* **** */

static
void bleep(void* p)
{
	if(_bleep_test(p))
		_bleep_fn(p);
}

int main(void)
{
//	strcpy((void*)0x0c000010, "DSKIMG");

	void *const dst = (void*)0x10000000U;
	void *const src = (void*)0x0c000000U + (((4 << 6) + (0 & 63)) << 11);

	(void)memcpy(dst, src, ((1 << 6) << 11));

	bleep(dst);
	bleep((void*)0x10020000);
}
