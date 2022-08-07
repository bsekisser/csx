#define CSX_PSR_BIT_N		31
#define CSX_PSR_BIT_Z		30
#define CSX_PSR_BIT_C		29
#define CSX_PSR_BIT_V		28

#define CSX_PSR_BIT_Q		27
#define CSX_PSR_BIT_J		24
#define CSX_PSR_BIT_GE0		16
#define CSX_PSR_BIT_E		9
#define CSX_PSR_BIT_T		5

#define CSX_PSR_N			_BV(CSX_PSR_BIT_N)
#define CSX_PSR_Z			_BV(CSX_PSR_BIT_Z)
#define CSX_PSR_C			_BV(CSX_PSR_BIT_C)
#define CSX_PSR_V			_BV(CSX_PSR_BIT_V)

#define CSX_PSR_NZ			(CSX_PSR_N | CSX_PSR_Z)
#define CSX_PSR_NZC			(CSX_PSR_NZ | CSX_PSR_C)
#define CSX_PSR_NZCV		(CSX_PSR_NZC | CSX_PSR_V)

#define CSX_PSR_Q			_BV(CSX_PSR_BIT_Q)
#define CSX_PSR_E			_BV(CSX_PSR_BIT_E)
#define CSX_PSR_GE_MASK		(_BM(4) << CSX_PSR_BIT_GE0)
#define CSX_PSR_T			_BV(CSX_PSR_BIT_T)

#define CSX_PSR_MASK		(CSX_PSR_NZCV | CSX_PSR_Q | CSX_PSR_GE_MASK | CSX_PSR_E)

/* **** */

#define CPSR				core->cpsr
#define SPSR				core->spsr

/* function prototypes */

uint8_t csx_core_check_cc(csx_core_p core, uint8_t cond);

void csx_core_flags_nz(csx_core_p core, uint32_t rd_v);
void csx_core_flags_nzcv_add(csx_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v);
void csx_core_flags_nzcv_sub(csx_core_p core, uint32_t rd_v, uint32_t s1_v, uint32_t s2_v);
