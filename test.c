#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
	unsigned int val = 0x12345678;

	printf("         %%#x -- %#x\n", val);
	printf("          %%p -- %p\n", &val);
//	printf("         %%#p -- %#p\n", &val); // warn invalid
	printf("   %%#PRIxPTR -- %#" PRIxPTR "\n", (uintptr_t)&val);
	printf("  %%#0PRIxPTR -- %#0" PRIxPTR "\n", (uintptr_t)&val);
	printf("%%#16PRIxPTR -- %#16" PRIxPTR "\n", (uintptr_t)&val);
	printf("%%#016PRIxPTR -- %#016" PRIxPTR "\n", (uintptr_t)&val);
}

