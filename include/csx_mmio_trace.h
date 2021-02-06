enum {
	MEM_READ_BIT = 0,
	MEM_WRITE_BIT,
	MEM_TRACE_READ_BIT,
	MEM_TRACE_WRITE_BIT,
};

#define MEM_READ (1 << MEM_READ_BIT)
#define MEM_WRITE (1 << MEM_WRITE_BIT)
#define MEM_READ_TRACE (1 << MEM_TRACE_READ_BIT)
#define MEM_WRITE_TRACE (1 << MEM_TRACE_WRITE_BIT)

#define MEM_RW (MEM_READ | MEM_WRITE)

#define MEM_TRACE_RW (MEM_READ_TRACE | MEM_WRITE_TRACE)

#define MEM_R_TRACE_R (MEM_READ | MEM_READ_TRACE)
#define MEM_RW_TRACE_RW (MEM_RW | MEM_TRACE_RW)

#undef MMIO
#define MMIO(_ahi, _alo, _dhi, _dlo, _size, _access, _name) \
	_name = ((_ahi ## ULL << 16) + _alo ## ULL),

enum {
	MMIO_LIST
};

typedef struct ea_trace_t* ea_trace_p;
typedef struct ea_trace_t {
	uint32_t	address;
	uint32_t	reset_value;
	uint8_t		size;
	uint32_t	access;
	const char *name;
}ea_trace_t;

#undef MMIO
#define MMIO(_ahi, _alo, _dhi, _dlo, _size, _access, _name) \
	{ ((_ahi ## ULL << 16) | _alo ## ULL), \
		((_dhi ## ULL << 16) | _dlo ## ULL), \
		((_size) >> 3), _access, #_name, },
	
static struct ea_trace_t trace_list[] = {
	MMIO_LIST
	{ 0ULL,0ULL,0,0UL,0 }
};

ea_trace_p csx_mmio_get_trace(ea_trace_p trace_list, uint32_t address);
ea_trace_p csx_mmio_trace(csx_mmio_p mmio, ea_trace_p tl, uint32_t address);
void csx_mmio_trace_reset(csx_mmio_p mmio, ea_trace_p tl, uint8_t* dst);
