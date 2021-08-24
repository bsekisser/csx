static csx_mmio_peripheral_t cfg_peripheral[2] = {
	[0] = {
		.base = CSX_MMIO_CFG_BASE,

		.reset = csx_mmio_cfg_reset,
		
		.read = csx_mmio_cfg_read,
		.write = csx_mmio_cfg_write,
	},

	[1] = {
		.base = CSX_MMIO_CFG_BASE + 0x100,

	//	.reset = csx_mmio_cfg_reset,
		
		.read = csx_mmio_cfg_read,
		.write = csx_mmio_cfg_write,
	}
};

static csx_mmio_peripheral_t dpll_peripheral = {
	.base = CSX_MMIO_DPLL_BASE,

	.reset = csx_mmio_dpll_reset,

	.read = csx_mmio_dpll_read,
	.write = csx_mmio_dpll_write,
};
