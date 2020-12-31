typedef struct csx_mmio_t* csx_mmio_p;

#define CSX_MMIO_BASE 0xfffb0000
#define CSX_MMIO_STOP 0xfffeffff
#define CSX_MMIO_SIZE (CSX_MMIO_STOP - CSX_MMIO_BASE + 1)

/* **** */

uint32_t csx_mmio_read(csx_p csx, uint32_t addr, uint8_t size);
void csx_mmio_write(csx_p csx, uint32_t addr, uint32_t value, uint8_t size);
int csx_mmio_init(csx_p csx);
