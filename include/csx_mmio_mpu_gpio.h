typedef struct csx_mmio_mpu_gpio_t** csx_mmio_mpu_gpio_h;
typedef struct csx_mmio_mpu_gpio_t* csx_mmio_mpu_gpio_p;

typedef struct csx_mmio_mpu_xgpio_t* csx_mmio_mpu_xgpio_p;
typedef struct csx_mmio_mpu_xgpio_t {
	csx_mmio_mpu_gpio_p		gpio;
	uint32_t				base;
	uint8_t					data[256];
}csx_mmio_mpu_xgpio_t;

typedef struct csx_mmio_mpu_gpio_t {
	csx_p					csx;
	csx_mmio_p				mmio;
	
	csx_mmio_mpu_xgpio_t	x[4];
}csx_mmio_mpu_gpio_t;

int csx_mmio_mpu_gpio_init(csx_p csx, csx_mmio_p mmio, csx_mmio_mpu_gpio_h h2gpio);
//uint32_t csx_mmio_mpu_gpio_read(csx_mmio_mpu_gpio_p gpio, uint32_t address, uint8_t size);
//void csx_mmio_mpu_gpio_reset(csx_mmio_mpu_gpio_p gpio);
//void csx_mmio_mpu_gpio_write(csx_mmio_mpu_gpio_p gpio, uint32_t address, uint32_t value, uint8_t size);
