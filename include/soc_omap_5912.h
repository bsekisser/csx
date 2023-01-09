#pragma once

/* **** forward defines, etc. */

typedef struct soc_t** soc_h;
typedef struct soc_t* soc_p;

#define MPU_TIMERt_BASE(_t)     (0xfffec500UL + ((_t - 1) << 8))
#define MPU_TIMER_(_t, _x)      (MPU_TIMERt_BASE(_t) + _MPU_TIMER_NAME(_t, _x))
#define MPU_TIMER_ENUM(_t, _x)  MPU_TIMER_NAME(_t, _x) = MPU_TIMER_(_t, _x)

#define MPU_TIMER_NAME(_t, _x)  MPU_ ## _x ## _TIMER ## _t
#define _MPU_TIMER_NAME(_t, _x)  _MPU_ ## _x ## _TIMER

enum {
	SOC_MMIO_START =			0xfffb0000UL,
	SOC_MPU_TIMER1_BASE =		MPU_TIMERt_BASE(1), /* 0xfffec500 */
	SOC_MPU_TIMER2_BASE =		MPU_TIMERt_BASE(2), /* 0xfffec600 */
	SOC_MPU_TIMER3_BASE =		MPU_TIMERt_BASE(3), /* 0xfffec700 */
	SOC_MPU_WDT_TIMER_BASE =	0xfffec800, /* MPU_TIMERt_BASE(4) */
	SOC_MMIO_END =				0xfffeffffUL,
};

#define SOC_MMIO_SIZE (1 + (SOC_MMIO_END - SOC_MMIO_START))

/* **** soc includes */

#include "soc_omap_timer.h"
#include "soc_omap_watchdog.h"

/* **** csx includes */

//#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */

/* **** system includes */

#include <stdint.h>

/* **** */

typedef struct soc_t {
	csx_p                   csx;
	soc_omap_timer_p        timer[3];
	soc_omap_watchdog_p     watchdog;
}soc_t;

int soc_omap5912_init(csx_p csx, soc_h h2soc);
