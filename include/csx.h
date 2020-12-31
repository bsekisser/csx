#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <capstone/capstone.h>

#include "err_test.h"
#include "data.h"

/* **** */

enum {
	NO_TRACE,
	__TRACE_ENTER_,
	__TRACE_EXIT_,
};

#if 1
	#define T(_x) _x
	#define TRACE(_f, args...) \
		printf("// %s:%s:%u: " _f ")\n", __FILE__, __FUNCTION__, __LINE__, ## args);
	#define _TRACE_(_m, _x) \
		do { \
			if(BIT_OF(_m->trace_flags, __TRACE_## _x ##_)) \
				LOG(); \
		}while(0);
	#define _TRACE_ENABLE_(_m, _x) \
		_m->trace_flags |= _BV(__TRACE_## _x ##_);
#else
	#define T(_x) 0
	#define TRACE(_f, args...)
#endif

typedef struct csx_core_t* csx_core_p;

typedef uint8_t csx_reg_t;
typedef csx_reg_t* csx_reg_p;

typedef uint32_t csx_state_t;

enum {
	CSX_STATE_HALT_BIT,
	CSX_STATE_RUN_BIT,
	CSX_STATE_INVALID_READ_BIT,
	CSX_STATE_INVALID_WRITE_BIT,
};

#define CSX_STATE_HALT				_BV(CSX_STATE_HALT_BIT)
#define CSX_STATE_RUN				_BV(CSX_STATE_RUN_BIT)
#define CSX_STATE_INVALID_READ		_BV(CSX_STATE_INVALID_READ_BIT)
#define CSX_STATE_INVALID_WRITE		_BV(CSX_STATE_INVALID_WRITE_BIT)

typedef struct csx_t* csx_p;

#include "csx_core_coprocessor.h"
#include "csx_mmio.h"
#include "csx_mmu.h"

typedef void (*csx_core_step_fn)(csx_core_p csx);

typedef struct csx_t {
	uint64_t			cycle;
	
	csx_state_t			state;
	csx_core_step_fn	step;

	csx_core_p			core;
	csx_coprocessor_p	cp;
	
	struct {
		csx_mmu_p			data;
		csx_mmu_read_fn		read;
		csx_mmu_write_fn	write;
	}mmu;
	
	csx_mmio_p			mmio;
	
	uint32_t			trace_flags;
	
	csh					handle;
}csx_t;
