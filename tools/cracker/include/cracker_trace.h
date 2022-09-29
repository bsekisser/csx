#include <stdio.h>

#define _CORE_TRACE_(_f, ...) \
		printf(_f, ##__VA_ARGS__);

#define CORE_TRACE(_f, ...) \
	({ \
		CORE_TRACE_START(); \
		CORE_TRACE_END(_f, ##__VA_ARGS__); \
	})

#define CORE_TRACE_START(_f, ...) \
	({ \
		int _thumb = IP & 1; \
		int _ip = IP & (_thumb ? ~1 : ~3); \
		_CORE_TRACE_("%c(0x%08x, 0x%08x, %s, " _f, _thumb ? 'T' : 'A', _ip, IR, CCs(1), ##__VA_ARGS__); \
	})

#define CORE_TRACE_END(_f, ...) \
	_CORE_TRACE_(_f ");\n", ##__VA_ARGS__);
