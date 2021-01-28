typedef struct csx_mmio_cfg_t** csx_mmio_cfg_h;
typedef struct csx_mmio_cfg_t* csx_mmio_cfg_p;
typedef struct csx_mmio_cfg_t {
	csx_p			csx;
	csx_mmio_p		mmio;

	uint32_t		oxfffe1160;
	
	struct	{
		uint32_t	ctrl;
	}mux[('D' - 'A') + 1];

	struct {
		uint32_t	mode_ctrl;
	}comp;

	uint32_t		mod_conf_ctrl_0;
	uint32_t		voltage_ctrl_0;
	uint32_t		reset_ctl;
}csx_mmio_cfg_t;

int csx_mmio_cfg_init(csx_p csx, csx_mmio_p mmio, csx_mmio_cfg_h cfg);
uint32_t csx_mmio_cfg_read(csx_mmio_cfg_p cfg, uint32_t address, uint8_t size);
void csx_mmio_cfg_reset(csx_mmio_cfg_p cfg);
void csx_mmio_cfg_write(csx_mmio_cfg_p cfg, uint32_t address, uint32_t value, uint8_t size);
