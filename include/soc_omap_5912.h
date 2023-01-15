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

//	MPU PUBLIC / SHARED

	SOC_UART1_BASE = 			0xfffb0000UL,	/* 0xfffb0000 - 0xfffb00ff */
//	SOC_USB_OTG_BASE =			0xfffb0700UL,	/* 0xfffb0700 - 0xfffb07ff */
	SOC_UART2_BASE = 			0xfffb0800UL,
//	SOC_MICROWIRE_BASE = 		0xfffb3000UL,	/* 0xfffb3000 - 0xfffb30ff */
//	SOC_USB_CLIENT_BASE =		0xfffb4000UL,	/* 0xfffb4000 - 0xfffb40ff */
//	SOC_RTC_BASE =				0xfffb4800UL,	/* 0xfffb4800 - 0xfffb48ff */
//	SOC_MPUIO_KEYBOARD_BASE =	0xfffb5000UL,	/* 0xfffb5000 - 0xfffb50ff */
//	SOC_PWL_BASE =				0xfffb5800UL,	/* 0xfffb5800 - 0xfffb58ff */
//	SOC_PWT_BASE =				0xfffb6000UL,	/* 0xfffb6000 - 0xfffb60ff */
//	SOC_MPU_MMC_BASE =			0xfffb7800UL,	/* 0xfffb7800 - 0xfffb78ff */
//	SOC_OS_TIMER_BASE =			0xfffb9000UL,	/* 0xfffb9000 - 0xfffb90ff */
//	SOC_USB_HC_BASE =			0xfffba000UL,	/* 0xfffba000 - 0xfffba0ff */
//	SOC_FAC_BASE =				0xfffba800UL,	/* 0xfffba800 - 0xfffba8ff */
//	SOC_LPG1_BASE =				0xfffbd000UL,	/* 0xfffbd000 - 0xfffbd0ff */
//	SOC_LPG2_BASE =				0xfffbd800UL,	/* 0xfffbd800 - 0xfffbd8ff */
	SOC_UART3_BASE = 			0xfffb9800UL,

//	MPU PRIVATE

//	SOC_MPU_L2_IHR_BASE =		0xfffe0000UL,	/* 0xfffe0000 - 0xfffe00ff */
//	SOC_LDCONV_BASE =			0xfffe3000UL,	/* 0xfffe3000 - 0xfffe30ff */
//	SOC_LCD_BASE =				0xfffec000UL,	/* 0xfffec000 - 0xfffec0ff */
//	SOC_MPU_L1_IHR_BASE =		0xfffecb00UL,	/* 0xfffecb00 - 0xfffecbff */
//	SOC_SYS_DMAC_BASE =			0xfffed800UL,	/*** 0xfffed800 - 0xfffedcff ***/
	SOC_MPU_TIMER1_BASE =		MPU_TIMERt_BASE(1), /* 0xfffec500 - 0xfffec5ff */
	SOC_MPU_TIMER2_BASE =		MPU_TIMERt_BASE(2), /* 0xfffec600 - 0xfffec6ff */
	SOC_MPU_TIMER3_BASE =		MPU_TIMERt_BASE(3), /* 0xfffec700 - 0xfffec7ff */
	SOC_MPU_WDT_BASE =			0xfffec800UL, /* MPU_TIMERt_BASE(4) -- 0xfffec800 - 0xfffec8ff */
	SOC_MMIO_END =				0xfffeffffUL,
};

enum {
	__SOC_MODULE_UART1,
	__SOC_MODULE_UART2,
	__SOC_MODULE_UART3,
	__SOC_MODULE_MPU_TIMER1,
	__SOC_MODULE_MPU_TIMER2,
	__SOC_MODULE_MPU_TIMER3,
	__SOC_MODULE_MPU_WDT,
	SOC_MMIO_MODULE_COUNT,
};

#define SOC_MMIO_SIZE (1 + (SOC_MMIO_END - SOC_MMIO_START))

/* **** soc includes */

#include "soc_omap_timer.h"
#include "soc_mmio_uart.h"
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
	soc_omap_uart_p			uart[3];
	soc_omap_watchdog_p     watchdog;
}soc_t;

int soc_omap5912_init(csx_p csx, soc_h h2soc);
