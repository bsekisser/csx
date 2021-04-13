typedef struct csx_mmio_mpu_l1_ihr_t** csx_mmio_mpu_l1_ihr_h;
typedef struct csx_mmio_mpu_l1_ihr_t* csx_mmio_mpu_l1_ihr_p;
typedef struct csx_mmio_mpu_l1_ihr_t {
	csx_p			csx;
	csx_mmio_p		mmio;

	uint8_t			data[256];
}csx_mmio_mpu_l1_ihr_t;

int csx_mmio_mpu_l1_ihr_init(csx_p csx, csx_mmio_p mmio, csx_mmio_mpu_l1_ihr_h h2mpu);
