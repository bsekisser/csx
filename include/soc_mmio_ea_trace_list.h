#undef MMIO
#define MMIO MMIO_TRACE
#define MMIO_TRACE(_ahi, _alo, _dhi, _dlo, _size, _access, _name) \
	{ MMIO_HILO(_ahi, _alo), \
		MMIO_HILO(_dhi, _dlo), \
			((_size) >> 3), _access, #_name, },

/* **** */

#ifndef TRACE_LIST
	#undef MMIO_TRACE_LIST_HEAD
	#define MMIO_TRACE_LIST_HEAD(_x) \
		static struct ea_trace_t trace_list_##_x[] = {

	#undef MMIO_TRACE_LIST_TAIL
	#define MMIO_TRACE_LIST_TAIL \
		MMIO(0, 0, 0, 0, 0, 0, 0) \
	};
#endif

/* **** */

#ifdef TRACE_LIST
	static struct ea_trace_t trace_list[] = { \
		MMIO_LIST \
		MMIO(0, 0, 0, 0, 0, 0, 0) \
	};
#endif

#define MMIO_TRACE_LIST MMIO_LIST
