typedef struct csx_mmu_t** csx_mmu_h;
typedef struct csx_mmu_t* csx_mmu_p;

/* **** */

#define CSX_FRAMEBUFFER_BASE	0x20000000
#define CSX_FRAMEBUFFER_STOP	0x2003e7ff
#define CSX_FRAMEBUFFER_SIZE	(CSX_FRAMEBUFFER_STOP - CSX_FRAMEBUFFER_BASE)

#define CSX_SDRAM_BASE			0x10000000
#define CSX_SDRAM_SIZE			(16 * 1024 * 1024)
#define CSX_SDRAM_STOP			(CSX_SDRAM_BASE + CSX_SDRAM_SIZE)

/* **** */

uint32_t csx_data_read(uint8_t* src, uint8_t size);
void csx_data_write(uint8_t* dst, uint32_t value, uint8_t size);

uint32_t csx_mmu_read(csx_mmu_p mmu, uint32_t addr, uint8_t size);
void csx_mmu_write(csx_mmu_p mmu, uint32_t addr, uint32_t value, uint8_t size);

int csx_mmu_init(csx_p csx, csx_mmu_h h2mmu);
