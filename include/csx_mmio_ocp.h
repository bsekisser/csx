typedef struct csx_mmio_ocp_t** csx_mmio_ocp_h;
typedef struct csx_mmio_ocp_t* csx_mmio_ocp_p;
typedef struct csx_mmio_ocp_t {
	csx_p			csx;
	csx_mmio_p		mmio;
	
	struct {
		uint32_t	adv_config;
		uint32_t	config;
	}emifs[4];
}csx_mmio_ocp_t;

int csx_mmio_ocp_init(csx_p csx, csx_mmio_p mmio, csx_mmio_ocp_h h2ocp);
//uint32_t csx_mmio_ocp_read(csx_mmio_ocp_p ocp, uint32_t address, uint8_t size);
//void csx_mmio_ocp_reset(csx_mmio_ocp_p ocp);
//void csx_mmio_ocp_write(csx_mmio_ocp_p ocp, uint32_t address, uint32_t value, uint8_t size);
