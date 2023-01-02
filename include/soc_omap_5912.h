#pragma once

#define MPU_TIMERt_BASE(_t)		(0xfffec500UL + ((_t - 1) << 8))
#define MPU_TIMER_(_t, _x)		(MPU_TIMERt_BASE(_t) + _MPU_TIMER_NAME(_t, _x))
#define MPU_TIMER_ENUM(_t, _x)  MPU_TIMER_NAME(_t, _x) = MPU_TIMER_(_t, _x)

#define MPU_TIMER_NAME(_t, _x)  MPU_ ## _x ## _TIMER ## _t
#define _MPU_TIMER_NAME(_t, _x)  _MPU_ ## _x ## _TIMER

enum {
    SOC_MMIO_START =        0xfffb0000UL,
    SOC_MPU_TIMER1_BASE =   MPU_TIMERt_BASE(1),
    SOC_MPU_TIMER2_BASE =   MPU_TIMERt_BASE(2),
    SOC_MPU_TIMER3_BASE =   MPU_TIMERt_BASE(3),
    SOC_MMIO_END =          0xfffeffffUL,
};

#define SOC_MMIO_SIZE (1 + (SOC_MMIO_END - SOC_MMIO_START))

/* **** module includes */

#include "soc_omap_timer.h"
//#include "soc_omap_watchdog.h"

/* **** project includes */

#include "soc_omap_5912.h"

#include "csx.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

typedef struct soc_t** soc_h;
typedef struct soc_t* soc_p;
typedef struct soc_t {
	csx_p					csx;
	soc_omap_timer_t		timer[3];
}soc_t;

const soc_t omap5912 = {
    SOC_MPU_TIMER_DECL(1),
    SOC_MPU_TIMER_DECL(2),
    SOC_MPU_TIMER_DECL(3),
};
