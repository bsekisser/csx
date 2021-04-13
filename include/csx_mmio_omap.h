#define CSX_MMIO_GP_TIMER_BASE		0xfffb1400
#define CSX_MMIO_OS_TIMER_BASE		0xfffb9000
#define CSX_MMIO_MPU_GPIO3_BASE		0xfffbb400
#define CSX_MMIO_MPU_GPIO4_BASE		0xfffbbc00
#define CSX_MMIO_MPU_GPIO1_BASE		0xfffbe400
#define CSX_MMIO_MPU_GPIO2_BASE		0xfffbec00
#define CSX_MMIO_CFG_BASE			0xfffe1000
#define CSX_MMIO_WATCHDOG_BASE		0xfffeb000
#define CSX_MMIO_TIMER_BASE			0xfffec500
#define CSX_MMIO_TIMER_WDT_BASE		0xfffec800
#define CSX_MMIO_MPU_L1_IHR_BASE	0xfffecb00
#define CSX_MMIO_OCP_BASE			0xfffecc00
#define CSX_MMIO_MPU_BASE			0xfffece00
#define CSX_MMIO_DPLL_BASE			0xfffecf00

#define CSX_MMIO_TIMER(_x)			(CSX_MMIO_TIMER_BASE + (((_x) & 0x03) << 8))
