#define CSX_MMIO_UART2_BASE			0xfffb0800UL
#define CSX_MMIO_GP_TIMER_BASE		0xfffb1400UL
#define CSX_MMIO_MPU_MMC1_BASE		0xfffb7800UL
#define CSX_MMIO_MPU_MMC2_BASE		0xfffb7c00UL
#define CSX_MMIO_OS_TIMER_BASE		0xfffb9000UL
#define CSX_MMIO_MPU_GPIO3_BASE		0xfffbb400UL
#define CSX_MMIO_MPU_GPIO4_BASE		0xfffbbc00UL
#define CSX_MMIO_MPU_GPIO1_BASE		0xfffbe400UL
#define CSX_MMIO_MPU_GPIO2_BASE		0xfffbec00UL
#define CSX_MMIO_MPU_L2_IHR_BASE	0xfffe0000UL
#define CSX_MMIO_MPU_L3_IHR_BASE	0xfffe0100UL
#define CSX_MMIO_MPU_L4_IHR_BASE	0xfffe0200UL
#define CSX_MMIO_MPU_L5_IHR_BASE	0xfffe0300UL
#define CSX_MMIO_CFG_BASE			0xfffe1000UL
#define CSX_MMIO_WATCHDOG_BASE		0xfffeb000UL
#define CSX_MMIO_TIMER_BASE			0xfffec500UL
#define CSX_MMIO_TIMER_WDT_BASE		0xfffec800UL
#define CSX_MMIO_MPU_L1_IHR_BASE	0xfffecb00UL
#define CSX_MMIO_OCP_BASE			0xfffecc00UL
#define CSX_MMIO_MPU_BASE			0xfffece00UL
#define CSX_MMIO_DPLL_BASE			0xfffecf00UL

#if 0
	#define CSX_MMIO_GP_TIMER(_t) \
		(CSX_MMIO_GP_TIMER_BASE + ((((_t) - 1U) & 0x07U) * 0x800U))
#else
	#define CSX_MMIO_GP_TIMER(_t) \
		(CSX_MMIO_GP_TIMER_BASE + (((((unsigned int)(_t)) - 1U) & 0x07U) << 11U))
#endif

#define CSX_MMIO_TIMER(_t) \
	(CSX_MMIO_TIMER_BASE + (((_t) & 0x03U) << 8U))
