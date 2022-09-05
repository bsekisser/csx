#include "soc.h"
#include "soc_core.h"
#include "soc_core_cp15.h"
#include "soc_data.h"
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

static void* _csx_soc_map_ppa(csx_p csx, uint32_t ppa, size_t size)
{
	void* data = 0;
	uint32_t ppo = ppa;
	
	if(0) LOG("csx = 0x%08x, ppa = 0x%08x, size = 0x%02x, ppo = 0x%08x",
		(uint)csx, ppa, size, ppo);

	const csx_data_p cdp = csx->cdp;
	const uint32_t cdp_end = cdp->base + cdp->size;
	
	if(_in_bounds(ppa, size, CSX_SDRAM_BASE, CSX_SDRAM_STOP)) {
		data = csx->sdram;
		ppo -= CSX_SDRAM_BASE;
	} else if(_in_bounds(ppa, size, cdp->base, cdp_end)) {
		data = cdp->data;
		ppo -= cdp->base;
	} else if(_in_bounds(ppa, size, CSX_FRAMEBUFFER_BASE, CSX_FRAMEBUFFER_STOP)) {
		data = csx->frame_buffer;
		ppo -= CSX_FRAMEBUFFER_BASE;
	} else
		return(0);

	if(0) LOG("csx = 0x%08x, ppa = 0x%08x, size = 0x%02x, data = 0x%08x, ppo = 0x%08x",
		(uint)csx, ppa, size, (uint)data, ppo);

	return(data + (ppo & PAGE_MASK));
}


static void _csx_soc_write_ppa(csx_p csx, uint32_t ppa, uint32_t data, size_t size)
{
	if(_in_bounds(ppa, size, CSX_MMIO_BASE, CSX_MMIO_STOP))
	{
		soc_mmio_write(csx->mmio, ppa, data, size);
	}
/* CSx FLASH ROM AREAS */
	else if(_in_bounds(ppa, size, 0x00000000, 0x03ffffff)) /* CS0 */
	{
/*
 * 0000 0000 - 0000 ffff -- Boot ROM
 * 0001 0000 - 0003 ffff -- Reserved Boot ROM
 * 0004 0000 - 01ff ffff -- Reserved
 * 0200 0000 - 03ff ffff -- NOR Flash
 * 
 */
		if(_in_bounds(ppa, size, 0x02000000, 0x03ffffff)) {
			soc_nnd_flash_write(csx->nnd, ppa, data, size);
		}
	}
	else if(_in_bounds(ppa, size, 0x04000000, 0x07ffffff)) /* CS1 */
	{
		soc_nnd_flash_write(csx->nnd, ppa, data, size);
	}
	else if(_in_bounds(ppa, size, 0x08000000, 0x0bffffff)) /* CS2 */
	{
		soc_nnd_flash_write(csx->nnd, ppa, data, size);
	}
	else if(_in_bounds(ppa, size, 0x0c000000, 0x0fffffff)) /* CS3 */
	{
		soc_nnd_flash_write(csx->nnd, ppa, data, size);
	}
	else {
		LOG("ppa = 0x%08x", ppa);
	}
}

/* **** */

uint32_t csx_soc_ifetch(csx_p csx, uint32_t va, size_t size)
{
	soc_tlbe_p tlbe = 0;

retry_read:;
	void* src = soc_tlb_ifetch(csx->tlb, va, &tlbe);
	if(0) LOG("src = 0x%08x, va = 0x%08x, tlbe = 0x%08x", (uint)src, va, (uint)tlbe);
	
retry_read_src:;
	if(src) {
		return(soc_data_read(src + PAGE_OFFSET(va), size));
	} else {
		uint32_t ppa = va;
		
		const int tlb = soc_mmu_vpa_to_ppa(csx->mmu, va, &ppa);
		src = _csx_soc_map_ppa(csx, ppa, size);

		if(tlb && src) {
			soc_tlb_fill_instruction_tlbe(tlbe, va, src);
			goto retry_read_src;
		} else
			return(csx_soc_read_ppa(csx, ppa, size, 0));
	}
	
	LOG("va = 0x%08x", va);

	return(0);
}


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

int csx_soc_main(int core_trace, int loader_firmware)
{
	int err = 0;
	csx_p csx = calloc(1, sizeof(csx_t));

	ERR_NULL(csx);
	if(!csx)
		return(-1);
	
	ERR(err = csx_soc_init(csx));
	csx_soc_reset(csx);

	const soc_core_p core = csx->core;

	core->trace = core_trace;

	if(loader_firmware)
		_csx_soc_init_load_rgn_file(csx, &csx->firmware, FIRMWARE_FileName);
	else
		_csx_soc_init_load_rgn_file(csx, &csx->loader, LOADER_FileName);

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
		}
	}

	LOG("CYCLE = 0x%016llx, IP = 0x%08x", csx->cycle, IP);

	return(err);
}

uint32_t csx_soc_read(csx_p csx, uint32_t va, size_t size)
{
	soc_tlbe_p tlbe = 0;

retry_read:;
	void* src = soc_tlb_read(csx->tlb, va, &tlbe);
retry_read_src:;
	if(src)
		return(soc_data_read(src + PAGE_OFFSET(va), size));
	else {
		uint32_t ppa = va;
		
		const int tlb = soc_mmu_vpa_to_ppa(csx->mmu, va, &ppa);
		src = _csx_soc_map_ppa(csx, ppa, size);

		if(tlb && src) {
			soc_tlb_fill_data_tlbe(tlbe, va, src);
			goto retry_read_src;
		} else
			return(csx_soc_read_ppa(csx, ppa, size, 0));
	}
	
	LOG("va = 0x%08x", va);
	
	return(0);
}

uint32_t csx_soc_read_ppa(csx_p csx, uint32_t ppa, size_t size, int mmu)
{
	uint32_t data = 0;

	if(_in_bounds(ppa, size, CSX_MMIO_BASE, CSX_MMIO_STOP))
	{
		data = soc_mmio_read(csx->mmio, ppa, size);
	}
/* CSx FLASH ROM AREAS */
	else if(_in_bounds(ppa, size, 0x00000000, 0x03ffffff)) /* CS0 */
	{
/*
 * 0000 0000 - 0000 ffff -- Boot ROM
 * 0001 0000 - 0003 ffff -- Reserved Boot ROM
 * 0004 0000 - 01ff ffff -- Reserved
 * 0200 0000 - 03ff ffff -- NOR Flash
 * 
 */
		if(_in_bounds(ppa, size, 0x02000000, 0x03ffffff)) {
			data = soc_nnd_flash_read(csx->nnd, ppa, size);
		}
	}
	else if(_in_bounds(ppa, size, 0x04000000, 0x07ffffff)) /* CS1 */
	{
		data = soc_nnd_flash_read(csx->nnd, ppa, size);
	}
	else if(_in_bounds(ppa, size, 0x08000000, 0x0bffffff)) /* CS2 */
	{
		data = soc_nnd_flash_read(csx->nnd, ppa, size);
	}
	else if(_in_bounds(ppa, size, 0x0c000000, 0x0cffffff)) /* CS3 */
	{
		data = soc_nnd_flash_read(csx->nnd, ppa, size);
	}
	else if(_in_bounds(ppa, size, 0xffff0000, 0xffffffff)) /* ??? */
	{
		data = soc_nnd_flash_read(csx->nnd, ppa, size);
	}
	else if(mmu) /* fallback for mmu */
	{
		void* src = _csx_soc_map_ppa(csx, ppa, size);
		if(src)
			data = soc_data_read(src, size);
	}
	else
	{
		LOG("ppa = 0x%08x", ppa);
	}
	
	return(data);
}

void csx_soc_reset(csx_p csx)
{
	soc_core_reset(csx->core);
	soc_mmio_reset(csx->mmio);
	soc_tlb_reset(csx->tlb);
}

void csx_soc_write(csx_p csx, uint32_t va, uint32_t data, size_t size)
{
	soc_tlbe_p tlbe = 0;

retry_write:;
	void* dst = soc_tlb_write(csx->tlb, va, &tlbe);
retry_write_dst:;
	if(dst)
		return(soc_data_write(dst + PAGE_OFFSET(va), data, size));
	else {
		uint32_t ppa = va;
		
		const int tlb = soc_mmu_vpa_to_ppa(csx->mmu, va, &ppa);
		dst = _csx_soc_map_ppa(csx, ppa, size);

		if(tlb && dst) {
			soc_tlb_fill_data_tlbe(tlbe, va, dst);
			goto retry_write_dst;
		} else
			return(_csx_soc_write_ppa(csx, ppa, data, size));
	}
	
	LOG("va = 0x%08x", va);
}
