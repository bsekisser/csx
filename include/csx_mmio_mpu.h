typedef struct csx_mmio_mpu_t** csx_mmio_mpu_h;
typedef struct csx_mmio_mpu_t* csx_mmio_mpu_p;
typedef struct csx_mmio_mpu_t {
	csx_p			csx;
	csx_mmio_p		mmio;

	uint32_t		arm_ckctl;
	uint32_t		arm_idlect[2];
	uint32_t		arm_rstct2;
	uint32_t		arm_sysst;
}csx_mmio_mpu_t;

int csx_mmio_mpu_init(csx_p csx, csx_mmio_p mmio, csx_mmio_mpu_h h2mpu);
//uint32_t csx_mmio_mpu_read(csx_mmio_mpu_p mpu, uint32_t address, uint8_t size);
//void csx_mmio_mpu_reset(csx_mmio_mpu_p mpu);
//void csx_mmio_mpu_write(csx_mmio_mpu_p mpu, uint32_t address, uint32_t value, uint8_t size);
