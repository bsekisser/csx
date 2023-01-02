#include "soc.h"
#include "soc_core.h"
#include "soc_core_cp15.h"
#include "csx_data.h"
#include "csx.h"
#include "csx_state.h"

/* **** */

#include "bitfield.h"
#include "bounds.h"
#include "err_test.h"
#include "log.h"
#include "page.h"

/* **** */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* **** */

#define CYCLE csx->cycle

#include "garmin_rgn.h"

/* **** */

static void _csx_soc_init_load_rgn_file(csx_p csx, csx_data_p cdp, const char* file_name)
{
	int fd;

	char out[256];
	snprintf(out, 254, "%s%s%s", LOCAL_RGNDIR, RGNFileName, file_name);

	LOG("opening %s", out);

	ERR(fd = open(out, O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));

	void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);

	csx->cdp = cdp;
//	cdp->base = 0x10020000; /* ? thoretical load address in sdram */
	cdp->base = 0x14000000; /* ? safer as unknown load address */
	cdp->data = data;
	cdp->size = sb.st_size;

	LOG("base = 0x%08x, data = 0x%08x, size = 0x%08x",
		cdp->base, (uint)cdp->data, cdp->size);

	close(fd);
}

static uint32_t _csx_soc_read_ppa(uint32_t ppa, size_t size, void** src, void* data_src, uint32_t base)
{
	uint32_t ppo = ppa - base;
	
	void* dspao = data_src + (ppo & PAGE_MASK);
	
	if(src)
		*src = dspao;
	
	return(csx_data_read(dspao + PAGE_OFFSET(ppa), size));
}

static void _csx_soc_write_ppa(uint32_t ppa, uint32_t data, size_t size, void** dst, void* data_dst, uint32_t base)
{
	uint32_t ppo = ppa - base;
	
	void* ddpao = data_dst + (ppo & PAGE_MASK);
	
	if(dst)
		*dst = ddpao;
	
	return(csx_data_write(ddpao + PAGE_OFFSET(ppa), data, size));
}

/* **** */

int csx_soc_init(csx_p csx)
{
	int err = 0;

	CYCLE = 0;
	
	ERR(err = soc_core_init(csx, &csx->core));
	ERR(err = soc_core_cp15_init(csx));
	ERR(err = soc_mmu_init(csx, &csx->mmu));
	ERR(err = soc_mmio_init(csx, &csx->mmio));
	ERR(err = soc_nnd_flash_init(csx, &csx->nnd));
	ERR(err = soc_tlb_init(csx, &csx->tlb));

	return(err);
}

int csx_soc_main(csx_h h2csx, int core_trace, int loader_firmware)
{
	int err = 0;
	csx_p csx = calloc(1, sizeof(csx_t));

	ERR_NULL(csx);
	if(!csx)
		return(-1);
	
	if(h2csx)
		*h2csx = csx;
	
	if(loader_firmware)
		_csx_soc_init_load_rgn_file(csx, &csx->firmware, FIRMWARE_FileName);
	else
		_csx_soc_init_load_rgn_file(csx, &csx->loader, LOADER_FileName);

	ERR(err = csx_soc_init(csx));
	csx_soc_reset(csx);

	const soc_core_p core = csx->core;

	core->trace = core_trace;

	if(!err)
	{
		csx->state = CSX_STATE_RUN;
		
		int limit = Mb(4) + Kb(0) + Kb(0);
		for(int i = 0; i < limit; i++)
		{
			csx->cycle++;
			core->step(core);

			if((csx->state & CSX_STATE_HALT) || (0 == PC))
			{
				i = limit;
				LOG_ACTION(break);
			}

			csx->insns++;
		}
	}

	LOG("CYCLE = 0x%016llx, IP = 0x%08x", csx->cycle, IP);

	return(err);
}

uint32_t csx_soc_read(csx_p csx, uint32_t ppa, size_t size)
{
	return(csx_soc_read_ppa(csx, ppa, size, 0));
}

uint32_t csx_soc_read_ppa(csx_p csx, uint32_t ppa, size_t size, void** src)
{
	if(src)
		*src = 0;

	switch(ppa) {
		/* EMIFS */
//		case 0x00000000 ... 0x03ffffff: /* CS0 -- 64M */
		case 0x00000000 ... 0x0000ffff: /* CS0 -- 64K -- Boot ROM */
		case 0x00010000 ... 0x0003ffff: /* CS0 -- 192K -- Reserved Boot ROM */
		case 0x00040000 ... 0x001fffff: /* CS0 -- reserved */
		case 0x00200000 ... 0x00203fff: /* CS0 -- reserved */
		case 0x00204000 ... 0x0020ffff: /* CS0 -- reserved */
		case 0x00210000 ... 0x0021000f: /* CS0 -- reserved */
		case 0x00210010 ... 0x0021002f: /* CS0 -- reserved */
		case 0x00210030 ... 0x01ffffff: /* CS0 -- reserved */
			break;
		case 0x02000000 ... 0x03ffffff: /* CS0 -- 32M */
		case 0x04000000 ... 0x07ffffff: /* CS1 -- 64M */
		case 0x08000000 ... 0x0bffffff: /* CS2 -- 64M */
		case 0x0c000000 ... 0x0fffffff: /* CS3 -- 64M */
			return(soc_nnd_flash_read(csx->nnd, ppa, size));
			break;
		/* EMIFF */
		case 0x10000000 ... 0x13ffffff: /* SDRAM -- 64M -- external */
			return(_csx_soc_read_ppa(ppa, size, src, csx->sdram, CSX_SDRAM_BASE));
			break;
		case 0x14000000 ... 0x1fffffff: /* reserved */
			break;
		/* L3 OCP T1 */
		case 0x20000000 ... 0x2003e7ff: /* Framebuffer -- 250K */
			return(_csx_soc_read_ppa(ppa, size, src, csx->frame_buffer, CSX_FRAMEBUFFER_BASE));
			break;
		case 0x2003e800 ... 0x2007cfff: /* reserved */
		case 0x2007d000 ... 0x2007d3ff: /* reserved */
		case 0x2007d400 ... 0x2007d7ff: /* reserved */
		case 0x2007d800 ... 0x2007dfff: /* Camera I/F -- reserved */
		/* L3 OCP T2 */
		case 0x30000000 ... 0x30000fff: /* reserved */
		case 0x30001000 ... 0x30001fff: /* reserved */
		case 0x30002000 ... 0x300021ff: /* reserved */
		case 0x30002200 ... 0x3007d7ff: /* reserved */
		case 0x3007d800 ... 0x3007dfff: /* Camera I/F -- reserved */
		case 0x3007e000 ... 0x30ffffff: /* reserved */
		case 0x31000000 ... 0x34ffffff: /* reserved */
		case 0x35000000 ... 0x7fffffff: /* reserved */
		/* DSP MPUI */
		case 0xe0000000 ... 0xe101ffff: /* MPUI memory & peripheral */
		case 0xe1020000 ... 0xefffffff: /* reserved */
		/* TIPB Peripheral and Control Registers */
		case 0xf0000000 ... 0xfffaffff: /* reserved */
			break;
		case 0xfffb0000 ... 0xfffeffff: /* OMAP 5912 peripherals */
			return(soc_mmio_read(csx->mmio, ppa, size));
			break;
		case 0xffff0000 ... 0xffffffff: /* reserved */
			break;
	}
	
	const csx_data_p cdp = csx->cdp;
	const uint32_t cdp_end = cdp->base + cdp->size;

	if(_in_bounds(ppa, size, cdp->base, cdp_end))
			return(_csx_soc_read_ppa(ppa, size, src, cdp->data, cdp->base));

	return(0);
}

void csx_soc_reset(csx_p csx)
{
	soc_core_reset(csx->core);
	soc_mmio_reset(csx->mmio);
	soc_tlb_reset(csx->tlb);
}

void csx_soc_write(csx_p csx, uint32_t ppa, uint32_t data, size_t size)
{
	return(csx_soc_write_ppa(csx, ppa, data, size, 0));
}

void csx_soc_write_ppa(csx_p csx, uint32_t ppa, uint32_t data, size_t size, void** dst)
{
	if(dst)
		*dst = 0;

	switch(ppa) {
		/* EMIFS */
//		case 0x00000000 ... 0x03ffffff: /* CS0 -- 64M */
		case 0x00000000 ... 0x0000ffff: /* CS0 -- 64K -- Boot ROM */
		case 0x00010000 ... 0x0003ffff: /* CS0 -- 192K -- Reserved Boot ROM */
		case 0x00040000 ... 0x001fffff: /* CS0 -- reserved */
		case 0x00200000 ... 0x00203fff: /* CS0 -- reserved */
		case 0x00204000 ... 0x0020ffff: /* CS0 -- reserved */
		case 0x00210000 ... 0x0021000f: /* CS0 -- reserved */
		case 0x00210010 ... 0x0021002f: /* CS0 -- reserved */
		case 0x00210030 ... 0x01ffffff: /* CS0 -- reserved */
			break;
		case 0x02000000 ... 0x03ffffff: /* CS0 -- 32M */
		case 0x04000000 ... 0x07ffffff: /* CS1 -- 64M */
		case 0x08000000 ... 0x0bffffff: /* CS2 -- 64M */
		case 0x0c000000 ... 0x0fffffff: /* CS3 -- 64M */
			return(soc_nnd_flash_write(csx->nnd, ppa, data, size));
			break;
		/* EMIFF */
		case 0x10000000 ... 0x13ffffff: /* SDRAM -- 64M -- external */
			return(_csx_soc_write_ppa(ppa, data, size, dst, csx->sdram, CSX_SDRAM_BASE));
			break;
		case 0x14000000 ... 0x1fffffff: /* reserved */
			break;
		/* L3 OCP T1 */
		case 0x20000000 ... 0x2003e7ff: /* Framebuffer -- 250K */
			return(_csx_soc_write_ppa(ppa, data, size, dst, csx->frame_buffer, CSX_FRAMEBUFFER_BASE));
			break;
		case 0x2003e800 ... 0x2007cfff: /* reserved */
		case 0x2007d000 ... 0x2007d3ff: /* reserved */
		case 0x2007d400 ... 0x2007d7ff: /* reserved */
		case 0x2007d800 ... 0x2007dfff: /* Camera I/F -- reserved */
		/* L3 OCP T2 */
		case 0x30000000 ... 0x30000fff: /* reserved */
		case 0x30001000 ... 0x30001fff: /* reserved */
		case 0x30002000 ... 0x300021ff: /* reserved */
		case 0x30002200 ... 0x3007d7ff: /* reserved */
		case 0x3007d800 ... 0x3007dfff: /* Camera I/F -- reserved */
		case 0x3007e000 ... 0x30ffffff: /* reserved */
		case 0x31000000 ... 0x34ffffff: /* reserved */
		case 0x35000000 ... 0x7fffffff: /* reserved */
		/* DSP MPUI */
		case 0xe0000000 ... 0xe101ffff: /* MPUI memory & peripheral */
		case 0xe1020000 ... 0xefffffff: /* reserved */
		/* TIPB Peripheral and Control Registers */
		case 0xf0000000 ... 0xfffaffff: /* reserved */
			break;
		case 0xfffb0000 ... 0xfffeffff: /* OMAP 5912 peripherals */
			return(soc_mmio_write(csx->mmio, ppa, data, size));
			break;
		case 0xffff0000 ... 0xffffffff: /* reserved */
			break;
	}
	
	const csx_data_p cdp = csx->cdp;
	const uint32_t cdp_end = cdp->base + cdp->size;

	assert(!_in_bounds(ppa, size, cdp->base, cdp_end));
//			return(_csx_soc_write_ppa(ppa, size, dst, cdp->data, cdp->base));
}
