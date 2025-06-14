#include <string.h>

/* **** */

extern
char *stpcpy(char *const dst, const char *const src)
{
	char *const p = mempcpy(dst, src, strlen(src));
	*p = 0;

	return(p);
}
