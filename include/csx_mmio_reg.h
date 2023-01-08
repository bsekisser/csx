#pragma once

/* **** forward type definitions */

typedef struct csx_mmio_reg_t* csx_mmio_reg_p;
typedef struct csx_mmio_reg_trace_t* csx_mmio_reg_trace_p;
typedef struct csx_mmio_regbit_t* csx_mmio_regbit_p;

/* **** csx includes */

#include "csx_mmio_reg_t.h"
#include "csx_mmio.h"
#include "csx_data.h"
#include "csx.h"

/* **** local includes */

#include "bitfield.h"

/* **** system includes */

#include <stdint.h>

/* **** */

static inline uint32_t csx_mmio_reg_get(csx_p csx, csx_mmio_reg_p cmr)
{
	void* src = csx_mmio_data_offset(csx, cmr->mpa);

	return(csx_data_read(src, cmr->size));
}

static inline void csx_mmio_reg_set(csx_p csx, csx_mmio_reg_p cmr, uint32_t data)
{
	void* dst = csx_mmio_data_offset(csx, cmr->mpa);

	csx_data_write(dst, data, cmr->size);
}

static inline void csx_mmio_regbit_bmas(csx_p csx, csx_mmio_regbit_p cmrb, uint32_t value)
{
	csx_mmio_reg_p reg = &cmrb->reg;

	uint32_t data = csx_mmio_reg_get(csx, reg);

	BMAS(data, cmrb->bit, value);

	csx_mmio_reg_set(csx, reg, data);
}

static inline void csx_mmio_regbit_clear(csx_p csx, csx_mmio_regbit_p cmrb)
{
	csx_mmio_regbit_bmas(csx, cmrb, 0);
}

static inline uint32_t csx_mmio_regbit_get(csx_p csx, csx_mmio_regbit_p cmrb)
{
	return(BEXT(csx_mmio_reg_get(csx, &cmrb->reg), cmrb->bit));
}

static inline void csx_mmio_regbit_set(csx_p csx, csx_mmio_regbit_p cmrb)
{
	csx_mmio_regbit_bmas(csx, cmrb, 1);
}
