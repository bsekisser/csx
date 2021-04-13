typedef struct csx_mmio_timer_t** csx_mmio_timer_h;
typedef struct csx_mmio_timer_t* csx_mmio_timer_p;
typedef struct csx_mmio_timer_t {
	csx_p			csx;
	csx_mmio_p		mmio;
	
	struct {
		uint64_t		base;
		uint32_t		cntl;
		uint32_t		value;
	}unit[3];
}csx_mmio_timer_t;

int csx_mmio_timer_init(csx_p csx, csx_mmio_p mmio, csx_mmio_timer_h h2t);
//uint32_t csx_mmio_timer_read(csx_mmio_timer_p t, uint32_t address, uint8_t size);
//void csx_mmio_timer_reset(csx_mmio_timer_p t);
//void csx_mmio_timer_write(csx_mmio_timer_p t, uint32_t address, uint32_t value, uint8_t size);
