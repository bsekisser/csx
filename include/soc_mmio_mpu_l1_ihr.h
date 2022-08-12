typedef struct soc_mmio_mpu_l1_ihr_t** soc_mmio_mpu_l1_ihr_h;
typedef struct soc_mmio_mpu_l1_ihr_t* soc_mmio_mpu_l1_ihr_p;
typedef struct soc_mmio_mpu_l1_ihr_t {
	csx_p			csx;
	soc_mmio_p		mmio;

	uint8_t			data[256];
}soc_mmio_mpu_l1_ihr_t;

int soc_mmio_mpu_l1_ihr_init(csx_p csx, soc_mmio_p mmio, soc_mmio_mpu_l1_ihr_h h2mpu);
