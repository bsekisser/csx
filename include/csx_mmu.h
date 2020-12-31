typedef struct csx_mmu_t* csx_mmu_p;

typedef uint32_t (*csx_mmu_read_fn)(csx_p csx, uint32_t addr, uint8_t size);
typedef void (*csx_mmu_write_fn)(csx_p csx, uint32_t addr, uint32_t value, uint8_t size);

/* **** */

uint32_t csx_data_read(uint8_t* src, uint8_t size);
void csx_data_write(uint8_t* dst, uint32_t value, uint8_t size);

int csx_mmu_init(csx_p csx);
