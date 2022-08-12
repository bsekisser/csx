typedef struct soc_mmio_os_timer_t** soc_mmio_os_timer_h;
typedef struct soc_mmio_os_timer_t* soc_mmio_os_timer_p;
typedef struct soc_mmio_os_timer_t {
	csx_p			csx;
	soc_mmio_p		mmio;
	
	uint64_t		base;
	uint32_t		tick_val;
//	uint32_t		tick_counter;
	uint32_t		ctrl;
}soc_mmio_os_timer_t;

int soc_mmio_os_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_os_timer_h h2ost);
//uint32_t soc_mmio_os_timer_read(soc_mmio_os_timer_p ost, uint32_t address, uint8_t size);
//void soc_mmio_os_timer_reset(soc_mmio_os_timer_p ost);
//void soc_mmio_os_timer_write(soc_mmio_os_timer_p ost, uint32_t address, uint32_t value, uint8_t size);
