#include "csx_armvm_glue.h"
#include "csx_soc.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx_soc_brom.h"
#include "csx_soc_omap.h"
#include "csx_soc_sram.h"
#include "csx_statistics.h"
#include "csx.h"
#include "csx_state.h"

/* **** */

#include "libarmvm/include/armvm_mem.h"
#include "libarmvm/include/armvm.h"

/* **** */

#include "libbse/include/action.h"
#include "libbse/include/bitfield.h"
#include "libbse/include/bounds.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/page.h"

/* **** */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* **** */

#include "garmin_rgn.h"

/* **** */

static int __csx_soc_init__cdp_copy(void* dst, csx_data_ref cdp, const uint32_t start, const uint32_t end)
{
	if(start > cdp->base)
		return(0);

	if(end < cdp->base)
		return(0);

	LOG("base: 0x%08x, start: 0x%08x, end: 0x%08x", cdp->base, start, end);

	void *const dst_start = dst + (cdp->base - start);
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

static void __csx_soc_init_cdp(csx_ref csx, csx_data_ref cdp)
{
	csx_soc_ref soc = csx->soc;

	__csx_soc_init__cdp_copy(csx->sdram, cdp,
		CSX_SDRAM_START, CSX_SDRAM_END);

	__csx_soc_init__cdp_copy(soc->sram, cdp,
		SOC_SRAM_START, SOC_SRAM_END);

	__csx_soc_init__cdp_copy(soc->brom, cdp,
		SOC_BROM_START, SOC_BROM_END);
}

static void _csx_soc_init_load_rgn_file(csx_ref csx, csx_data_ref cdp, const char* file_path)
{
	int fd;

	LOG("opening %s", file_path);

	ERR(fd = open(file_path, O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));

	void *const data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);

	cdp->data = data;
	cdp->size = sb.st_size;

	__csx_soc_init_cdp(csx, cdp);

	LOG("base = 0x%08x, data = 0x%08" PRIxPTR ", size = 0x%08zx",
		cdp->base, (uintptr_t)cdp->data, cdp->size);

	close(fd);
}

/* **** */

static
int csx_soc_action_exit(int err, void *const param, action_ref)
{
	ACTION_LOG(exit);

	/* **** */

	handle_ptrfree(param);

	/* **** */

	return(err);
}

static
action_handler_t csx_soc_action_sublist[] = {
	{{ .list = &csx_soc_brom_action_list }, { .is_list = 1 }, 0 },
	{{ .list = &csx_soc_sram_action_list }, { .is_list = 1 }, 0 },
	{{0}, { 0 }, 0 }
};

action_list_t csx_soc_action_list = {
	.list = {
		[_ACTION_EXIT] = {{ csx_soc_action_exit }, { 0 }, 0 },
	},

	.sublist = csx_soc_action_sublist
};

csx_soc_ptr csx_soc_alloc(csx_ref csx, csx_soc_href h2soc)
{
	ERR_NULL(csx);
	ERR_NULL(h2soc);

	ACTION_LOG(alloc);

	/* **** */

	csx_soc_ref soc = handle_calloc(h2soc, 1, sizeof(csx_soc_t));
	ERR_NULL(soc);

	soc->csx = csx;

	return(soc);
}

static int x038201000610(csx_ref csx) {
	switch(PC) {
		case 0x10020074:
		case 0x100200f0:
		case 0x10020168:
		case 0x1002026c:
		case 0x10025204:
		case 0x10025628:
		case 0x10026146:
		case 0x1002616a:
		case 0x10026bb0:
		case 0x10026dfe:
		case 0x10026e10:
		case 0x10026e22:
		case 0x10027128:
		case 0x1002a3c0:
		case 0x100314fc:
		case 0x10033c66:
		case 0x10034418:
			return(1);
	}

	return(0);
}

int csx_soc_main(csx_ref csx, const int core_trace, const int loader_firmware)
{
	pARMVM_CORE->config.trace = core_trace;

	int err = 0;

//	loader_firmware = 1;

	if(loader_firmware) {
		csx->firmware.base = 0x10020000;
		_csx_soc_init_load_rgn_file(csx, &csx->firmware, kGARMIN_RGN_FIRMWARE);
	} else {
		csx->loader.base = 0x10020000;
		_csx_soc_init_load_rgn_file(csx, &csx->loader, kGARMIN_RGN_LOADER);
	}

//	csx_data_ref cdp = loader_firmware ? &csx->firmware : &csx->loader;

	if(!err)
	{
		csx->state = CSX_STATE_RUN;

		unsigned saved_trace = pARMVM_CORE->config.trace;
		unsigned pc_skip = 0;

		uint32_t next_pc = 0;

		for(;;) {
			if(pc_skip) {
				if(PC >= next_pc) {
					pARMVM_CORE->config.trace = saved_trace;
					pc_skip = 0;
				}
			} else if(pARMVM_CORE->config.trace) {
				if(0) pc_skip = x038201000610(csx);

				if(pc_skip) {
					next_pc = PC + (4 >> IF_CPSR(Thumb));
					armvm_step(pARMVM);
					saved_trace = pARMVM_CORE->config.trace;
					pARMVM_CORE->config.trace = 0;
				}
			}

			if(0 > armvm_step(pARMVM))
				break;

			if((csx->state & CSX_STATE_HALT) || (0 == PC))
			{
				LOG_ACTION(break);
			}

			if(0 && (ICOUNT > 0x100000)) break;
			if(0 && (ICOUNT > 0x0a0d80)) break;
			if(0 && (ICOUNT > 0x0a0d80)) break;
			if(0 && (ICOUNT > 0x070000)) break;
			if(0 && (ICOUNT > 0x000010)) break;
		}
	}

	LOG("CYCLE = 0x%016" PRIx64 ", IP = 0x%08x, PC = 0x%08x", CYCLE, IP, PC);

	return(err);
}
