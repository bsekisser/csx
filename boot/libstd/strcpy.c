#include <string.h>

/* **** */

extern
char *strcpy(char *const dst, const char *const src)
{
	stpcpy(dst, src);

	return(dst);
}
