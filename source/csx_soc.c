#include "csx_armvm_glue.h"
#include "csx_soc.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx_sdl.h"
#include "csx_soc_brom.h"
#include "csx_soc_omap.h"
#include "csx_soc_sram.h"
#include "csx_state.h"
#include "csx_statistics.h"
#include "csx.h"

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
#include <pthread.h>
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

ACTION_LIST(csx_soc_action_list,
	.list = {
		[_ACTION_EXIT] = {{ csx_soc_action_exit }, { 0 }, 0 },
	},

	SUBLIST(csx_soc_action_sublist),
);

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

static
void* csx_threaded_run(void* param)
{
	csx_ref csx = param;

	armvm_threaded_run(pARMVM);

	csx->state = 0;
	return(0);
}

static __attribute__((unused))
int csx_threaded_start(csx_ref csx)
{ return(pthread_create(&csx->thread, 0, csx_threaded_run, csx)); }

static const int sdl = 1;
static const int threaded = 1;

int csx_soc_main(csx_ref csx, const int core_trace, const int loader_firmware)
{
	pARMVM_CORE->config.trace = core_trace;

	int err = 0;

	if(loader_firmware) {
		csx->firmware.base = 0x10020000;
		_csx_soc_init_load_rgn_file(csx, &csx->firmware, kGARMIN_RGN_FIRMWARE);

		if(0)
			armvm_gpr(pARMVM, ARMVM_GPR(PC), &csx->firmware.base);
	} else if(0) {
		csx->loader.base = 0x10020000;
		_csx_soc_init_load_rgn_file(csx, &csx->loader, kGARMIN_RGN_LOADER);

		armvm_gpr(pARMVM, ARMVM_GPR(PC), &csx->loader.base);
	}

	if(sdl)
		csx_sdl_init(csx);

	if(!err)
	{
		csx->state = CSX_STATE_RUN;

		if(threaded)
			armvm_threaded_start(pARMVM);

		unsigned cycle = 0;

		for(;(CSX_STATE_RUN & csx->state);) {
			if(!threaded) {
				if(0 > armvm_step(pARMVM))
					csx->state = 0;
			}

			if(sdl && (cycle++ & 0x7fff))
				csx_sdl_step(csx);
		}
	}

	LOG("CYCLE = 0x%016" PRIx64 ", IP = 0x%08x, PC = 0x%08x", CYCLE, IP, PC);

	return(err);
}
