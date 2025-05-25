#include <string.h>

/* **** */

char *strcpy(char *const dst, const char *const src)
{
	stpcpy(dst, src);

	return(dst);
}
