typedef struct csx_mmu_t** csx_mmu_h;
typedef struct csx_mmu_t* csx_mmu_p;

typedef struct soc_mmu_tlb_t** soc_mmu_tlb_h;
typedef struct soc_mmu_tlb_t* soc_mmu_tlb_p;
typedef struct soc_mmu_tlb_t {
	void*							data;
	uint32_t						vp:20;
	uint32_t						ur:1;
	uint32_t						uw:1;
	uint32_t						ux:1;
	uint32_t						r:1;
	uint32_t						w:1;
	uint32_t						x:1;
	uint32_t						i:1;
}soc_mmu_tlb_t;

/* **** */

#define CSX_FRAMEBUFFER_BASE	0x20000000
#define CSX_FRAMEBUFFER_STOP	0x2003e7ff
#define CSX_FRAMEBUFFER_SIZE	(CSX_FRAMEBUFFER_STOP - CSX_FRAMEBUFFER_BASE)

#define CSX_SDRAM_BASE			0x10000000
#define CSX_SDRAM_SIZE			(16 * 1024 * 1024)
#define CSX_SDRAM_STOP			(CSX_SDRAM_BASE + CSX_SDRAM_SIZE)

/* **** */

uint32_t soc_data_read(uint8_t* src, uint8_t size);
void soc_data_write(uint8_t* dst, uint32_t value, uint8_t size);

int csx_mmu_read(csx_mmu_p mmu, uint32_t va, uint32_t* data, size_t size);
int csx_mmu_write(csx_mmu_p mmu, uint32_t va, uint32_t data, size_t size);

int csx_mmu_init(csx_p csx, csx_mmu_h h2mmu);
