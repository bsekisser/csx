#pragma once

#include <stdio.h>

enum {
	NO_TRACE,
	__TRACE_ENTER_,
	__TRACE_EXIT_,
};

typedef struct csx_trace_t* csx_trace_p;
typedef struct csx_trace_t {
	uint32_t	start;
	uint32_t	stop;
}csx_trace_t;

#if 1
	#define T(_x) _x
	#define TRACE(_f, args...) \
		printf("// %s:%s:%u: " _f ")\n", __FILE__, __FUNCTION__, __LINE__, ## args);
	#define _TRACE_(_m, _x) \
		do { \
			if(BEXT(_m->trace_flags, __TRACE_## _x ##_)) \
				LOG(); \
		}while(0);
	#define _TRACE_ENABLE_(_m, _x) \
		_m->trace_flags |= _BV(__TRACE_## _x ##_);
#else
	#define T(_x)
	#define TRACE(_f, args...)
	#define _TRACE_ENABLE_(_m, _x)
#endif
