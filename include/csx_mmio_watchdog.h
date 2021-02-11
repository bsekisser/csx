typedef struct csx_mmio_watchdog_t** csx_mmio_watchdog_h;
typedef struct csx_mmio_watchdog_t* csx_mmio_watchdog_p;
typedef struct csx_mmio_watchdog_t {
	csx_p			csx;
	csx_mmio_p		mmio;
	
	uint32_t		wspr;
	uint32_t		wwps;
	
	struct {
		uint32_t	mode;
	}timer;
}csx_mmio_watchdog_t;

int csx_mmio_watchdog_init(csx_p csx, csx_mmio_p mmio, csx_mmio_watchdog_h wdt);
//uint32_t csx_mmio_watchdog_read(csx_mmio_watchdog_p wdt, uint32_t address, uint8_t size);
//void csx_mmio_watchdog_reset(csx_mmio_watchdog_p wdt);
//void csx_mmio_watchdog_write(csx_mmio_watchdog_p wdt, uint32_t address, uint32_t value, uint8_t size);
