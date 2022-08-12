typedef struct soc_mmio_mpu_t** soc_mmio_mpu_h;
typedef struct soc_mmio_mpu_t* soc_mmio_mpu_p;
typedef struct soc_mmio_mpu_t {
	csx_p			csx;
	soc_mmio_p		mmio;

	uint32_t		arm_ckctl;
	uint32_t		arm_idlect[2];
	uint32_t		arm_rstct2;
	uint32_t		arm_sysst;
}soc_mmio_mpu_t;

int soc_mmio_mpu_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_h h2mpu);
//uint32_t soc_mmio_mpu_read(soc_mmio_mpu_p mpu, uint32_t address, uint8_t size);
//void soc_mmio_mpu_reset(soc_mmio_mpu_p mpu);
//void soc_mmio_mpu_write(soc_mmio_mpu_p mpu, uint32_t address, uint32_t value, uint8_t size);
