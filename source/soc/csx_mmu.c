#include <assert.h>

#include "csx.h"
#include "csx_core.h"

/* **** */

#define LOCAL_RGNDIR "../../garmin/rgn_files/"
#include "../../garmin/rgn_files/038201000610.h"

#define LOCAL_RGNFileName "_loader.bin"
//#define LOCAL_RGNFileName "_firmware.bin"

typedef struct csx_mmu_t* csx_mmu_p;
typedef struct csx_mmu_t {
	csx_p			csx;
	struct {
		uint8_t*	data;
		uint32_t	size;
	}loader;
	struct {
		uint8_t*	data;
		uint32_t	size;
	}firmware;
	uint8_t			sdram[CSX_SDRAM_SIZE];
	uint8_t			frame_buffer[CSX_FRAMEBUFFER_SIZE];
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

uint32_t csx_mmu_read(csx_mmu_p mmu, uint32_t addr, uint8_t size)
{
	assert((size == 1) || (size == 2) || (size == 4));

	const csx_p csx = mmu->csx;
	
	if(_in_bounds(addr, size, 0, mmu->loader.size))
		return(csx_data_read(&mmu->loader.data[addr], size));
	if(_in_bounds(addr, size, CSX_SDRAM_BASE, CSX_SDRAM_STOP))
		return(csx_data_read(&mmu->sdram[addr - CSX_SDRAM_BASE], size));
//	else if(_in_bounds(addr, size, CSX_FRAMEBUFFER_BASE, CSX_FRAMEBUFFER_STOP))
//		return(csx_data_read(&mmu->frame_buffer[addr - CSX_FRAMEBUFFER_BASE], size));
	else if(_in_bounds(addr, size, CSX_MMIO_BASE, CSX_MMIO_STOP))
		return(csx_mmio_read(csx->mmio, addr, size));

	LOG("addr = 0x%08x", addr);
//	LOG("csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ)");
	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));

	return(0);
}

void csx_mmu_write(csx_mmu_p mmu, uint32_t addr, uint32_t value, uint8_t size)
{
	assert((size == 1) || (size == 2) || (size == 4));

	const csx_p csx = mmu->csx;
	
	if(_in_bounds(addr, size, CSX_SDRAM_BASE, CSX_SDRAM_STOP))
		return(csx_data_write(&mmu->sdram[addr - CSX_SDRAM_BASE], value, size));
	else if(_in_bounds(addr, size, CSX_FRAMEBUFFER_BASE, CSX_FRAMEBUFFER_STOP))
		return(csx_data_write(&mmu->frame_buffer[addr - CSX_FRAMEBUFFER_BASE], value, size));
	else if(_in_bounds(addr, size, CSX_MMIO_BASE, CSX_MMIO_STOP))
		return(csx_mmio_write(csx->mmio, addr, value, size));

	LOG("addr = 0x%08x", addr);
//	LOG("csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE)");
	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
}

int csx_mmu_init(csx_p csx, csx_mmu_h h2mmu)
{
	csx_mmu_p mmu;
	
	ERR_NULL(mmu = malloc(sizeof(csx_mmu_t)));
	if(!mmu)
		return(-1);
	
	mmu->csx = csx;
	*h2mmu = mmu;
	
	int fd;

	LOG("opening " LOCAL_RGNDIR RGNFileName LOCAL_RGNFileName);

	ERR(fd = open(LOCAL_RGNDIR RGNFileName LOCAL_RGNFileName, O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));
	
	void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);
	
	mmu->loader.data = data;
	mmu->loader.size = sb.st_size;

	const uint32_t base = 0x10020000 - CSX_SDRAM_BASE;
	memcpy(&mmu->sdram[base], mmu->loader.data, mmu->loader.size);
	
	LOG("data = 0x%08x, size = 0x%08x", (uint32_t)mmu->loader.data, mmu->loader.size);
	
	close(fd);

	return(0);
}
