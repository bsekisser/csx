#include <string.h>

/* **** */

void* mempcpy(void *const dst, const void *const src, const size_t n)
{ return(memcpy(dst, src, n) + n); }
