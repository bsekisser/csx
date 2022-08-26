#undef MMIO
#define MMIO MMIO_ENUM
#define MMIO_ENUM(_ahi, _alo, _dhi, _dlo, _size, _access, _name) \
	_name = MMIO_HILO(_ahi, _alo),

/* **** */

#undef MMIO_TRACE_LIST_HEAD
#define MMIO_TRACE_LIST_HEAD(_x)

#undef MMIO_TRACE_LIST_TAIL
#define MMIO_TRACE_LIST_TAIL

#define MMIO_ENUM_LIST \
	enum { \
		MMIO_LIST \
	};

/* **** */

#ifdef TRACE_LIST
	MMIO_ENUM_LIST
#endif
