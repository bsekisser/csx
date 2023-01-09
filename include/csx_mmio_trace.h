/* **** forward defines/declarations */

typedef struct csx_mmio_trace_t* csx_mmio_trace_p;

/* **** system includes */

#include <stdint.h>

/* **** */

enum {
	_Rw = 1,
	_rW = 2,
	_RW = 3,
};

#ifndef MMIO_HILO
	#define MMIO_HILO(_hi, _lo) (((_hi) << 16) | (_lo))
#endif

#define MMIO_TRACE_T(_ahi, _alo, _size, _access, _dhi, _dlo, _name) \
	{ \
		.access = _ ## _access, \
		.mpa = MMIO_HILO(_ahi, _alo), \
		.name = # _name, \
		.reset_value = MMIO_HILO(_dhi, _dlo), \
		.size = ((_size) >> 4), \
	},

#define MMIO_TRACE_ENUM(_ahi, _alo, _size, _access, _dhi, _dlo, _name) \
	_name = MMIO_HILO(_ahi, _alo),
