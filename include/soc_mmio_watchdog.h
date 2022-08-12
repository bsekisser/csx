typedef struct soc_mmio_watchdog_t** soc_mmio_watchdog_h;
typedef struct soc_mmio_watchdog_t* soc_mmio_watchdog_p;
typedef struct soc_mmio_watchdog_t {
	csx_p			csx;
	soc_mmio_p		mmio;
	
	uint32_t		wspr;
	uint32_t		wwps;
	
	struct {
		uint32_t	mode;
	}timer;
}soc_mmio_watchdog_t;

int soc_mmio_watchdog_init(csx_p csx, soc_mmio_p mmio, soc_mmio_watchdog_h wdt);
//uint32_t soc_mmio_watchdog_read(soc_mmio_watchdog_p wdt, uint32_t address, uint8_t size);
//void soc_mmio_watchdog_reset(soc_mmio_watchdog_p wdt);
//void soc_mmio_watchdog_write(soc_mmio_watchdog_p wdt, uint32_t address, uint32_t value, uint8_t size);
