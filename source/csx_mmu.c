#include "csx.h"

//#define LOCAL_RGNDIR "../garmin/rgn_files/"
#define LOCAL_RGNDIR "/mnt/local/garmin/rgn_files/"
//#include "../../garmin/rgn_files/038201000610.h"
#include "../garmin/rgn_files/038201000610.h"

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
}csx_mmu_t;

uint32_t csx_data_read(uint8_t* src, uint8_t size)
{
	uint32_t res = 0;

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}


uint32_t csx_mmu_read(csx_p csx, uint32_t addr, uint8_t size)
{
	csx_mmu_p mmu = csx->mmu;
	
	if(addr <= mmu->loader.size)
		return(csx_data_read(&mmu->loader.data[addr], size));
	else if(addr >= 0xfffe000)
		return(csx_mmio_read(csx, addr, size));
	
	return(0);
}

void csx_mmu_write(csx_p csx, uint32_t addr, uint32_t value, uint8_t size)
{
	csx_mmu_p mmu = csx->mmu;
	
	if(addr >= 0xfffe000)
		csx_mmio_write(csx, addr, value, size);
}

int csx_mmu_init(csx_p csx)
{
	csx_mmu_p mmu;
	
	ERR_NULL(mmu = malloc(sizeof(csx_mmu_t)));
	if(!mmu)
		return(1);
	
	csx->mmu = mmu;
	
	int fd;

	LOG("opening " LOCAL_RGNDIR RGNFileName "_loader.bin...");

	ERR(fd = open(LOCAL_RGNDIR RGNFileName "_loader.bin", O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));
	
	void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);
	
	mmu->loader.data = data;
	mmu->loader.size = sb.st_size;
	
	close(fd);

	return(0);
}
