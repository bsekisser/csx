#pragma once

/* **** forward defines, etc. */

typedef struct soc_t** soc_h;
typedef struct soc_t* soc_p;

#define MPU_TIMERt_BASE(_t)     (0xfffec500UL + ((((unsigned int)(_t)) - 1U) << 8U))
#define MPU_TIMER_(_t, _x)      (MPU_TIMERt_BASE(_t) + _MPU_TIMER_NAME(_t, _x))
#define MPU_TIMER_ENUM(_t, _x)  MPU_TIMER_NAME(_t, _x) = MPU_TIMER_(_t, _x)

#define MPU_TIMER_NAME(_t, _x)  MPU_ ## _x ## _TIMER ## _t
#define _MPU_TIMER_NAME(_t, _x)  _MPU_ ## _x ## _TIMER

#define SOC_MMIO_START				0xfffb0000UL
#define SOC_MPU_TIMER1_BASE			MPU_TIMERt_BASE(1U) /* 0xfffec500 */
#define SOC_MPU_TIMER2_BASE			MPU_TIMERt_BASE(2U) /* 0xfffec600 */
#define SOC_MPU_TIMER3_BASE			MPU_TIMERt_BASE(3U) /* 0xfffec700 */
#define SOC_MPU_WDT_TIMER_BASE		0xfffec800UL /* MPU_TIMERt_BASE(4) */
#define SOC_MMIO_END				0xfffeffffUL

#define SOC_MMIO_SIZE (1U + (SOC_MMIO_END - SOC_MMIO_START))

/* **** soc includes */

#include "soc_omap_timer.h"
#include "soc_omap_watchdog.h"

/* **** csx includes */

//#include "csx_mmio.h"
#include "csx.h"

/* **** local includes */

#include "callback_list.h"

/* **** system includes */

#include <stdint.h>

/* **** */

typedef struct soc_t { // TODO: rename, move to soc.h
	csx_p                   csx;
	soc_omap_timer_p        timer[3];
	soc_omap_watchdog_p     watchdog;
	
	callback_list_t			atexit_list;
	callback_list_t			reset_list;
}soc_t;

int soc_omap5912_init(csx_p csx, soc_h h2soc);
