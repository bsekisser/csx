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

#include "err_test.h"
#include "data.h"

typedef struct csx_mmu_t* csx_mmu_p;

typedef uint8_t csx_reg_t;
typedef csx_reg_t* csx_reg_p;

typedef uint32_t csx_state_t;

enum {
	CSX_STATE_HALT_BIT,
	CSX_STATE_RUN_BIT,
};

#define CSX_STATE_HALT (1 << ((sizeof(csx_state_t) - 1) - CSX_STATE_HALT_BIT))
#define CSX_STATE_RUN (1 << ((sizeof(csx_state_t) - 1) - CSX_STATE_RUN_BIT))

typedef struct csx_t* csx_p;
typedef struct csx_t {
	uint32_t	reg[16];
	uint32_t	pc;
	uint32_t	cpsr;
	uint32_t	spsr;
	const char*	ccs;
	
	csx_state_t	state;
	csx_mmu_p	mmu;
}csx_t;

#define rLR 14
#define rPC 15

#define INSN_PC (0x10 | (rPC))

#define CSX_PSR_BIT_N		31
#define CSX_PSR_BIT_Z		30
#define CSX_PSR_BIT_C		29
#define CSX_PSR_BIT_V		28

#define CSX_PSR_BIT_Q		27
#define CSX_PSR_BIT_GE0		16
#define CSX_PSR_BIT_E		9

#define CSX_PSR_N			(1 << CSX_PSR_BIT_N)
#define CSX_PSR_Z			(1 << CSX_PSR_BIT_Z)
#define CSX_PSR_C			(1 << CSX_PSR_BIT_C)
#define CSX_PSR_V			(1 << CSX_PSR_BIT_V)

#define CSX_PSR_NZC		(CSX_PSR_N | CSX_PSR_Z | CSX_PSR_C)
#define CSX_PSR_NZCV	(CSX_PSR_NZC | CSX_PSR_V)

#define CSX_PSR_Q			(1 << CSX_PSR_BIT_Q)
#define CSX_PSR_E			(1 << CSX_PSR_BIT_E)
#define CSX_PSR_GE_MASK		(((1 << 4) - 1) << CSX_PSR_BIT_GE0)

#define CSX_PSR_MASK	(CSX_PSR_NZCV | CSX_PSR_Q | CSX_PSR_GE_MASK | CSX_PSR_E)

/* csx_core.c */

uint32_t csx_reg_get(csx_p csx, csx_reg_t r);
void csx_reg_set(csx_p csx, csx_reg_t r, uint32_t v);

void csx_core_step(csx_p csx);
int csx_core_init(csx_p* csx);

/* csx_mmio.c */

uint32_t csx_mmio_read(csx_p csx, uint32_t addr, uint8_t size);
void csx_mmio_write(csx_p csx, uint32_t addr, uint32_t value, uint8_t size);
int csx_mmio_init(csx_p csx);

/* csx_mmu.c */

uint32_t csx_mmu_read(csx_p csx, uint32_t addr, uint8_t size);
void csx_mmu_write(csx_p csx, uint32_t addr, uint32_t value, uint8_t size);
int csx_mmu_init(csx_p csx);
