typedef struct csx_mmio_dpll_t** csx_mmio_dpll_h;
typedef struct csx_mmio_dpll_t* csx_mmio_dpll_p;
typedef struct csx_mmio_dpll_t {
	csx_p			csx;
	csx_mmio_p		mmio;

	uint32_t		ctl_reg[1];
}csx_mmio_dpll_t;

int csx_mmio_dpll_init(csx_p csx, csx_mmio_p mmio, csx_mmio_dpll_h h2dpll);
uint32_t csx_mmio_dpll_read(csx_mmio_dpll_p dpll, uint32_t address, uint8_t size);
void csx_mmio_dpll_reset(csx_mmio_dpll_p dpll);
void csx_mmio_dpll_write(csx_mmio_dpll_p dpll, uint32_t address, uint32_t value, uint8_t size);
