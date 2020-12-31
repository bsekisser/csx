#include "csx.h"
#include "csx_core.h"

/* **** */

#define CSX_SDRAM_BASE	0x10000000
#define CSX_SDRAM_SIZE	(16 * 1024 * 1024)
#define CSX_SDRAM_STOP	(CSX_SDRAM_BASE + CSX_SDRAM_SIZE)

/* **** */

#define LOCAL_RGNDIR "../../garmin/rgn_files/"
#include "../../garmin/rgn_files/038201000610.h"

typedef struct csx_mmu_t* csx_mmu_p;
typedef struct csx_mmu_t {
	struct {
		uint8_t*	data;
		uint32_t	size;
	}loader;
	struct {
		uint8_t*	data;
		uint32_t	size;
	}firmware;
	uint8_t			sdram[CSX_SDRAM_SIZE];
}csx_mmu_t;

/* **** */

uint32_t csx_data_read(uint8_t* src, uint8_t size)
{
	uint32_t res = 0;

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

void csx_data_write(uint8_t* dst, uint32_t value, uint8_t size)
{
	for(int i = 0; i < size; i++)
	{
		*dst++ = value & 0xff;
		value >>= 8;
	}
}


uint32_t csx_mmu_read(csx_p csx, uint32_t addr, uint8_t size)
{
	csx_mmu_p mmu = csx->mmu.data;

	if(_in_bounds(addr, 0, mmu->loader.size))
		return(csx_data_read(&mmu->loader.data[addr], size));
	if(_in_bounds(addr, CSX_SDRAM_BASE, CSX_SDRAM_STOP))
		return(csx_data_read(&mmu->sdram[addr - CSX_SDRAM_BASE], size));
	else if(_in_bounds(addr, CSX_MMIO_BASE, CSX_MMIO_STOP))
		return(csx_mmio_read(csx, addr, size));

	LOG("addr = 0x%08x", addr);
	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));

	return(0);
}

void csx_mmu_write(csx_p csx, uint32_t addr, uint32_t value, uint8_t size)
{
	csx_mmu_p mmu = csx->mmu.data;

	if(_in_bounds(addr, CSX_SDRAM_BASE, CSX_SDRAM_STOP))
		return(csx_data_write(&mmu->sdram[addr - CSX_SDRAM_BASE], value, size));
	else if(_in_bounds(addr, CSX_MMIO_BASE, CSX_MMIO_STOP))
		return(csx_mmio_write(csx, addr, value, size));

	LOG("addr = 0x%08x", addr);
//	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
}

int csx_mmu_init(csx_p csx)
{
	csx_mmu_p mmu;
	
	ERR_NULL(mmu = malloc(sizeof(csx_mmu_t)));
	if(!mmu)
		return(-1);
	
	csx->mmu.data = mmu;
	csx->mmu.read = csx_mmu_read;
	csx->mmu.write = csx_mmu_write;
	
	int fd;

	LOG("opening " LOCAL_RGNDIR RGNFileName "_firmware.bin...");

	ERR(fd = open(LOCAL_RGNDIR RGNFileName "_firmware.bin", O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));
	
	void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);
	
	mmu->loader.data = data;
	mmu->loader.size = sb.st_size;
	
	close(fd);

	return(0);
}
