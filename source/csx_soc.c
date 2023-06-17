#include "soc.h"

/* **** soc includes */

#include "soc_core.h"
#include "soc_core_cp15.h"
#include "soc.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx_mem.h"
#include "csx_soc_omap.h"
#include "csx_statistics.h"
#include "csx.h"
#include "csx_state.h"

/* **** */

#include "bitfield.h"
#include "bounds.h"
#include "callback_list.h"
#include "err_test.h"
#include "handle.h"
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

static int _csx_soc_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	csx_soc_h h2soc = param;
	csx_soc_p soc = *h2soc;

	callback_list_process(&soc->atexit_list);

	handle_free(param);

	return(0);
}

static int __csx_soc_init__cdp_copy(void* dst, csx_data_p cdp, uint32_t start, uint32_t end)
{
	if(start > cdp->base)
		return(0);
	
	if(end < cdp->base)
		return(0);

	LOG("base: 0x%08x, start: 0x%08x, end: 0x%08x", cdp->base, start, end);

	void* dst_start = dst + (cdp->base - start);
	const void* src = cdp->data;

	const void* dst_limit = dst + (end - start);
	const void* dst_end = dst_start + cdp->size;

	const size_t count = (dst_end <= dst_limit) ?
		cdp->size : (size_t)(dst_limit - dst_start);

	if(0) {
		LOG_START("dst: 0x%08" PRIxPTR, (uintptr_t)dst);
		_LOG_(" --- start: 0x%08" PRIxPTR, (uintptr_t)dst_start);
		_LOG_(" <-->> end: 0x%08" PRIxPTR, (uintptr_t)dst_end);
		_LOG_(" <<--> limit: 0x%08" PRIxPTR, (uintptr_t)dst_limit);
		LOG_END(", count: 0x%08zx", count);
	}

	if(count)
		memcpy(dst_start, src, count);

	return(1);
}

static void __csx_soc_init_cdp(csx_p csx, csx_data_p cdp)
{
	csx_soc_p soc = csx->soc;
	
	__csx_soc_init__cdp_copy(csx->sdram, cdp,
		CSX_SDRAM_START, CSX_SDRAM_END);

	__csx_soc_init__cdp_copy(soc->sram, cdp,
		SOC_SRAM_START, SOC_SRAM_END);

	__csx_soc_init__cdp_copy(soc->brom, cdp,
		SOC_BROM_START, SOC_BROM_END);
}

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

	cdp->data = data;
	cdp->size = sb.st_size;

	__csx_soc_init_cdp(csx, cdp);

	LOG("base = 0x%08x, data = 0x%08" PRIxPTR ", size = 0x%08zx",
		cdp->base, (uintptr_t)cdp->data, cdp->size);

	close(fd);
}

static int _csx_soc_reset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	csx_soc_p soc = param;
//	csx_p csx = soc->csx;

	callback_list_process(&soc->atreset_list);

	return(0);
}

/* **** */

DECL_CALLBACK_REGISTER_FN(csx_soc, csx_soc_p, soc, atexit)
DECL_CALLBACK_REGISTER_FN(csx_soc, csx_soc_p, soc, atreset)

int csx_soc_init(csx_p csx, csx_soc_h h2soc)
{
	if(_trace_init) {
		LOG();
	}

	assert(0 != csx);
	assert(0 != h2soc);

	csx_soc_p soc = HANDLE_CALLOC(h2soc, 1, sizeof(csx_soc_t));
	ERR_NULL(soc);
	
	soc->csx = csx;
	
	callback_list_init(&soc->atexit_list, 0, LIST_LIFO);
	callback_list_init(&soc->atreset_list, 0, LIST_FIFO);
	
	csx_callback_atexit(csx, _csx_soc_atexit, h2soc);
	csx_callback_atreset(csx, _csx_soc_reset, soc);

	csx_mem_mmap(csx, SOC_BROM_START, SOC_BROM_END, 0, soc->brom);
	csx_mem_mmap(csx, SOC_SRAM_START, SOC_SRAM_END, 0, soc->sram);

	int err = 0;

	CYCLE = 0;

	// TODO: fix soc module locations into soc

	ERR(err = soc_core_init(csx, &csx->core));
	ERR(err = soc_core_cp15_init(csx));
	ERR(err = soc_mmu_init(csx, &csx->mmu));
	ERR(err = soc_tlb_init(csx, &csx->tlb));

//	soc_omap5912_init(csx, &csx->soc);

	return(err);
}

int csx_soc_main(csx_p csx, int core_trace, int loader_firmware)
{
	int err = 0;

	const soc_core_p core = csx->core;

	core->trace = !!core_trace;

	csx_soc_reset(csx);

	csx->loader.base = EMIFS_CS0_RESERVED_BOOT_ROM_START;
	_csx_soc_init_load_rgn_file(csx, &csx->loader, LOADER_FileName);
	
	if(loader_firmware) {
		csx->firmware.base = 0x10020000;
	} else {
		if(1) {
			csx->loader.base = 0x10020000;
			__csx_soc_init_cdp(csx, &csx->loader);

			csx->firmware.base = csx->loader.base + csx->loader.size;
		} else
			csx->firmware.base = 0x10020000;

		csx->loader.base = EMIFS_CS0_RESERVED_BOOT_ROM_START;
	}

//	_csx_soc_init_load_rgn_file(csx, &csx->firmware, FIRMWARE_FileName);

	soc_core_psr_mode_switch(core, (CPSR & ~0x1f) | (0x18 + 7));

	csx_data_p cdp = loader_firmware ? &csx->firmware : &csx->loader;
	soc_core_reg_set_pcx(core, cdp->base);

if(0)	soc_core_reg_set(core, 12, 1);

	if(!err)
	{
		csx->state = CSX_STATE_RUN;

		for(;;) {
			csx->cycle++;
			core->step(core);

			if((csx->state & CSX_STATE_HALT) || (0 == PC))
			{
				LOG_ACTION(break);
			}

			csx->insns++;
if(1)		if(csx->insns > 0x100000)
				break;
		}
	}

	LOG("CYCLE = 0x%016" PRIx64 ", IP = 0x%08x, PC = 0x%08x", csx->cycle, IP, PC);

	return(err);
}

void csx_soc_reset(csx_p csx)
{
	_csx_soc_reset(csx->soc);
}
