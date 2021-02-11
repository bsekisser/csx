typedef struct csx_mmio_cfg_t** csx_mmio_cfg_h;
typedef struct csx_mmio_cfg_t* csx_mmio_cfg_p;
typedef struct csx_mmio_cfg_t {
	csx_p			csx;
	csx_mmio_p		mmio;

	uint8_t			data[0x1ff];
}csx_mmio_cfg_t;

int csx_mmio_cfg_init(csx_p csx, csx_mmio_p mmio, csx_mmio_cfg_h cfg);
//uint32_t csx_mmio_cfg_read(csx_mmio_cfg_p cfg, uint32_t address, uint8_t size);
//void csx_mmio_cfg_reset(csx_mmio_cfg_p cfg);
//void csx_mmio_cfg_write(csx_mmio_cfg_p cfg, uint32_t address, uint32_t value, uint8_t size);
