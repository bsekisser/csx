#include <assert.h>
#include <stdint.h>

/* **** */

static __attribute__((constructor, used))
void __stdint_preflight_checks__(void)
{
	assert(2 == sizeof(int16_t));
	assert(4 == sizeof(int32_t));
	assert(8 == sizeof(int64_t));
	assert(1 == sizeof(int8_t));

	assert(2 == sizeof(uint16_t));
	assert(4 == sizeof(uint32_t));
	assert(8 == sizeof(uint64_t));
	assert(1 == sizeof(uint8_t));
}
