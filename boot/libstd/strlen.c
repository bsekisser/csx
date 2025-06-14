#include <string.h>

/* **** */

extern
size_t strlen(const char *const src)
{
	size_t bytes = 0;

	while(src[bytes])
		bytes++;

	return(bytes);
}
