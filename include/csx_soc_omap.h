#pragma once

enum {
	EMIFS_CS0_BOOT_ROM_START = 			0x00000000U,
	EMIFS_CS0_BOOT_ROM_END =			0x0000ffffU,
	EMIFS_CS0_RESERVED_BOOT_ROM_START =	0x00010000U,
	EMIFS_CS0_RESERVED_BOOT_ROM_END = 	0x0003ffffU,
	EMIFS_CS0_FLASH_START =				0x02000000U,
	EMIFS_CS0_FLASH_END =				0x03ffffffU,

	SOC_BROM_START = EMIFS_CS0_BOOT_ROM_START,
	SOC_BROM_END = EMIFS_CS0_RESERVED_BOOT_ROM_END,
	SOC_BROM_ALLOC = (1 + (SOC_BROM_END - EMIFS_CS0_BOOT_ROM_START)),
};

enum {
	EMIFS_CS1_FLASH_START =				0x04000000U,
	EMIFS_CS1a_FLASH_START =			0x04000000U,
	EMIFS_CS1a_FLASH_END =				0x05ffffffU,
	EMIFS_CS1b_FLASH_START =			0x06000000U,
	EMIFS_CS1b_FLASH_END =				0x07ffffffU,
	EMIFS_CS1_FLASH_END =				0x07ffffffU,
};
	
enum {
	EMIFS_CS2_FLASH_START =				0x08000000U,
	EMIFS_CS2a_FLASH_START =			0x08000000U,
	EMIFS_CS2a_FLASH_END =				0x09ffffffU,
	EMIFS_CS2b_FLASH_START =			0x0a000000U,
	EMIFS_CS2b_FLASH_END =				0x0bffffffU,
	EMIFS_CS2_FLASH_END =				0x0bffffffU,
};

enum {
	EMIFS_CS3_FLASH_START =				0x0c000000U,
	EMIFS_CS3_FLASH_END =				0x0fffffffU,
};

enum {
	EMIFF_SDRAM_START =					0x10000000U,
	EMIFF_SDRAM_16Mb =					0x10ffffffU,
	EMIFF_SDRAM_32Mb =					0x11ffffffU,
	EMIFF_SDRAM_64Mb =					0x13ffffffU,

//	EMIFF_SDRAM_END = EMIFF_SDRAM_16Mb,
	EMIFF_SDRAM_END = EMIFF_SDRAM_64Mb,

	CSX_SDRAM_START = EMIFF_SDRAM_START,
	CSX_SDRAM_END = EMIFF_SDRAM_END,
	CSX_SDRAM_ALLOC = (1 + (CSX_SDRAM_END - CSX_SDRAM_START)),
};

enum {
	L3_OCP_T1_SRAM_START =				0x20000000U,
//	L3_OCP_T1_SRAM_END =				0x2003e7ffU, /* TODO: fudgit */
	L3_OCP_T1_SRAM_END =				0x2003efffU,

	SOC_SRAM_START = L3_OCP_T1_SRAM_START,
	SOC_SRAM_END = L3_OCP_T1_SRAM_END,
	SOC_SRAM_ALLOC = (1 + (SOC_SRAM_END - SOC_SRAM_START)),
};

enum {
	TIPB_MMIO_START = 					0xfffb0000U,

	SOC_OMAP_UART1 =					0xfffb0000U,
	SOC_OMAP_UART2 =					0xfffb0800U,
	SOC_OMAP_GP_TIMER =					0xfffb1400U,
	SOC_OMAP_USB_CLIENT =				0xfffb4000U,
	SOC_OMAP_MPU_MMC1_BASE =			0xfffb7800U,
	SOC_OMAP_MPU_MMC2_BASE =			0xfffb7c00U,
	SOC_OMAP_OS_TIMER =					0xfffb9000U,
	SOC_OMAP_UART3 =					0xfffb9800U,
	SOC_OMAP_MPU_GPIO3 =				0xfffbb400U,
	SOC_OMAP_MPU_GPIO4 =				0xfffbbc00U,
	SOC_OMAP_MPU_GPIO1 =				0xfffbe400U,
	SOC_OMAP_MPU_GPIO2 =				0xfffbec00U,

	SOC_OMAP_MPU_IHR_L2 =				0xfffe0000U,
	SOC_OMAP_CFG0 =						0xfffe1000U,
	SOC_OMAP_CFG1 =						0xfffe1100U,
	SOC_OMAP_WATCHDOG =					0xfffeb000U,
	SOC_OMAP_MPU_TIMER1 =				0xfffec500U,
	SOC_OMAP_MPU_TIMER2 =				0xfffec600U,
	SOC_OMAP_MPU_TIMER3 =				0xfffec700U,
	SOC_OMAP_MPU_TIMER4_WDT =			0xfffec800U,
	SOC_OMAP_MPU_IHR_L1 =				0xfffecb00U,
	SOC_OMAP_TC_EMIFS =					0xfffecc00U,
	SOC_OMAP_MPU =						0xfffece00U,
	SOC_OMAP_DPLL =						0xfffecf00U,

	TIPB_MMIO_END = 					0xfffeffffU,

	CSX_MMIO_ALLOC = (1 + (TIPB_MMIO_END - TIPB_MMIO_START)),
};
