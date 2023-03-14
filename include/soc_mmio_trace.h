#pragma once

/* **** */

typedef struct ea_trace_t* ea_trace_p;

/* **** */

#include "csx.h"

/* **** */

#include "soc_mmio.h"

/* **** */

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

#define MMIO_HILO(_hi, _lo) \
	((((_hi ## ULL) & 0xffff) << 16) | ((_lo ## ULL) & 0xffff))

#ifdef TRACE_LIST
	#include "soc_mmio_ea_trace_enum.h"
#endif

typedef struct ea_trace_t {
	uint32_t	address;
	uint32_t	reset_value;
	size_t		size;
	uint32_t	access;
	const char *name;
}ea_trace_t;

#ifdef TRACE_LIST
	#include "soc_mmio_ea_trace_list.h"
#endif
		
ea_trace_p soc_mmio_get_trace(ea_trace_p trace_list, uint32_t address);
ea_trace_p soc_mmio_trace(soc_mmio_p mmio, ea_trace_p tl, uint32_t address);
void soc_mmio_trace_reset(soc_mmio_p mmio, ea_trace_p tl, uint module);
