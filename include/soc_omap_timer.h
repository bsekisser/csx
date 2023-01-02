#pragma once

/* **** module includes */

typedef struct soc_omap_timer_t* soc_omap_timer_p;

/* **** project includes */

#include "soc_omap_5912.h"

#include "csx_mmio_reg.h"
#include "csx.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

enum {
	_MPU_CNTL_TIMER,
	_MPU_LOAD_TIMER = 4,
	_MPU_READ_TIMER = 8,
};

enum {
	_MPU_TIMER1_BASE = MPU_TIMERt_BASE(1),
	MPU_TIMER_ENUM(1, CNTL),
	MPU_TIMER_ENUM(1, LOAD),
	MPU_TIMER_ENUM(1, READ),

	_MPU_TIMER2_BASE = MPU_TIMERt_BASE(2),
	MPU_TIMER_ENUM(2, CNTL),
	MPU_TIMER_ENUM(2, LOAD),
	MPU_TIMER_ENUM(2, READ),

	_MPU_TIMER3_BASE = MPU_TIMERt_BASE(3),
	MPU_TIMER_ENUM(3, CNTL),
	MPU_TIMER_ENUM(3, LOAD),
	MPU_TIMER_ENUM(3, READ),
};


//CSX_MMIO_REG_DECL(MPU_CNTL_TIMER1, MPU_TIMERt_BASE(0), sizeof(uint32_t))
//CSX_MMIO_REG_DECL(MPU_LOAD_TIMER1, MPU_TIMERt_BASE(0), sizeof(uint32_t))
//CSX_MMIO_REG_DECL(MPU_READ_TIMER1, MPU_TIMERt_BASE(0), sizeof(uint32_t))

//CSX_MMIO_REG_DECL(MPU_CNTL_TIMER2, MPU_TIMERt_BASE(1), sizeof(uint32_t))
//CSX_MMIO_REG_DECL(MPU_LOAD_TIMER2, MPU_TIMERt_BASE(1), sizeof(uint32_t))
//CSX_MMIO_REG_DECL(MPU_READ_TIMER2, MPU_TIMERt_BASE(1), sizeof(uint32_t))

//CSX_MMIO_REG_DECL(MPU_CNTL_TIMER3, MPU_TIMERt_BASE(2), sizeof(uint32_t))
//CSX_MMIO_REG_DECL(MPU_LOAD_TIMER3, MPU_TIMERt_BASE(2), sizeof(uint32_t))
//CSX_MMIO_REG_DECL(MPU_READ_TIMER3, MPU_TIMERt_BASE(2), sizeof(uint32_t))

#define SOC_MPU_TIMER_DECL(_t) \
    .timer[_t - 1] = { \
		.r_mpu_cntl_timer = CSX_MMIO_REG_T_DECL(MPU_TIMER_(_t, CNTL), uint32_t), \
		.r_mpu_read_timer = CSX_MMIO_REG_T_DECL(MPU_TIMER_(_t, READ), uint32_t), \
		.r_mpu_load_timer = CSX_MMIO_REG_T_DECL(MPU_TIMER_(_t, LOAD), uint32_t), \
    }

typedef struct soc_omap_timer_t {
	csx_p					csx;

	uint64_t				cycle;

	csx_mmio_reg_t			r_mpu_cntl_timer;
	csx_mmio_reg_t			r_mpu_load_timer;
	csx_mmio_reg_t			r_mpu_read_timer;
}soc_omap_timer_t;

/* **** */

void soc_omap_timer_init(csx_p csx, soc_omap_timer_p timer);
