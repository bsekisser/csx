typedef struct csx_mmio_os_timer_t** csx_mmio_os_timer_h;
typedef struct csx_mmio_os_timer_t* csx_mmio_os_timer_p;
typedef struct csx_mmio_os_timer_t {
	csx_p			csx;
	csx_mmio_p		mmio;
	
	uint64_t		base;
	uint32_t		tick_val;
//	uint32_t		tick_counter;
	uint32_t		ctrl;
}csx_mmio_os_timer_t;

int csx_mmio_os_timer_init(csx_p csx, csx_mmio_p mmio, csx_mmio_os_timer_h h2ost);
//uint32_t csx_mmio_os_timer_read(csx_mmio_os_timer_p ost, uint32_t address, uint8_t size);
//void csx_mmio_os_timer_reset(csx_mmio_os_timer_p ost);
//void csx_mmio_os_timer_write(csx_mmio_os_timer_p ost, uint32_t address, uint32_t value, uint8_t size);
