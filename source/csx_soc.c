#include "soc.h"

/* **** soc includes */

#include "soc_core.h"
#include "soc_core_cp15.h"
//#include "soc_omap_5912.h"
#include "soc.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx_mem.h"
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
	cdp->data = data;
	cdp->size = sb.st_size;

	if(1) {
		cdp->base = 0x10020000; /* ? thoretical load address in sdram */

		void* src = cdp->data;
		void* dst = &csx->sdram[cdp->base - CSX_SDRAM_BASE];
		
		memcpy(dst, src, cdp->size);
	} else
		cdp->base = 0x14000000; /* ? safer as unknown load address */

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

	csx_mem_mmap(csx, CSX_SRAM_BASE, CSX_SRAM_END, 0, soc->sram);

	int err = 0;

	CYCLE = 0;

	// TODO: fix soc module locations into soc

	ERR(err = soc_core_init(csx, &csx->core));
	ERR(err = soc_core_cp15_init(csx));
	ERR(err = soc_mmu_init(csx, &csx->mmu));
//	ERR(err = soc_mmio_init(csx, &csx->mmio));
//	ERR(err = soc_nnd_flash_init(csx, &csx->nnd));
	ERR(err = soc_tlb_init(csx, &csx->tlb));

//	soc_omap5912_init(csx, &csx->soc);

	return(err);
}

int csx_soc_main(csx_p csx, int core_trace, int loader_firmware)
{
	int err = 0;

	if(loader_firmware)
		_csx_soc_init_load_rgn_file(csx, &csx->firmware, FIRMWARE_FileName);
	else
		_csx_soc_init_load_rgn_file(csx, &csx->loader, LOADER_FileName);

	csx_soc_reset(csx);

	const soc_core_p core = csx->core;

	core->trace = core_trace;

	if(!err)
	{
		csx->state = CSX_STATE_RUN;

		int limit = Mb(4) + Kb(0) + Kb(0);
//		int limit = Mb(18) + Kb(0) + Kb(0);
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

	LOG("CYCLE = 0x%016" PRIx64 ", IP = 0x%08x", csx->cycle, IP);

	return(err);
}

void csx_soc_reset(csx_p csx)
{
	_csx_soc_reset(csx->soc);
}
