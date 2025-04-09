#include "csx_armvm_glue.h"
#include "csx_soc.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx_soc_brom.h"
#include "csx_soc_omap.h"
#include "csx_statistics.h"
#include "csx.h"
#include "csx_state.h"

/* **** */

#include "libarmvm/include/armvm_mem.h"
#include "libarmvm/include/armvm.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/bounds.h"
#include "libbse/include/callback_qlist.h"
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

static int _csx_soc_atexit(void* param)
{
	if(_trace_atexit) {
		LOG(">>");
	}

	csx_soc_h h2soc = param;
	csx_soc_p soc = *h2soc;

	callback_qlist_process(&soc->atexit.list);

	if(_trace_atexit_pedantic) {
		LOG("--");
	}

	handle_free(param);

	if(_trace_atexit_pedantic) {
		LOG("<<");
	}

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

static int _csx_soc_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	csx_soc_p soc = param;
//	csx_p csx = soc->csx;

	callback_qlist_process(&soc->atreset.list);

	return(0);
}

/* **** */

csx_soc_p csx_soc_alloc(csx_p csx, csx_soc_h h2soc)
{
	ERR_NULL(csx);
	ERR_NULL(h2soc);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	csx_soc_p soc = HANDLE_CALLOC(h2soc, 1, sizeof(csx_soc_t));
	ERR_NULL(soc);

	soc->csx = csx;

	callback_qlist_init(&soc->atexit.list, LIST_LIFO);
	callback_qlist_init(&soc->atreset.list, LIST_FIFO);

	/* **** */

	csx_callback_atexit(csx, &soc->atexit.elem, _csx_soc_atexit, h2soc);
	csx_callback_atreset(csx, &soc->atreset.elem, _csx_soc_atreset, soc);

	/* **** */

	return(soc);
}

void csx_soc_callback_atexit(csx_soc_p soc,
	callback_qlist_elem_p cble, callback_fn fn, void* param)
{
	callback_qlist_setup_and_register_callback(&soc->atexit.list, cble, fn, param);
}

void csx_soc_callback_atreset(csx_soc_p soc,
	callback_qlist_elem_p cble, callback_fn fn, void* param)
{
	callback_qlist_setup_and_register_callback(&soc->atreset.list, cble, fn, param);
}

void csx_soc_init(csx_soc_p soc)
{
	ERR_NULL(soc);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_p csx = soc->csx;

	armvm_mem_mmap_ro(pARMVM_MEM, SOC_BROM_START, SOC_BROM_END, soc->brom);
	armvm_mem_mmap_rw(pARMVM_MEM, SOC_SRAM_START, SOC_SRAM_END, soc->sram);

	/* **** */
}

static int x038201000610(csx_p csx) {
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

int csx_soc_main(csx_p csx, int core_trace, int loader_firmware)
{
	pARMVM_CORE->config.trace = core_trace;

	int err = 0;

	csx->loader.base = EMIFS_CS0_RESERVED_BOOT_ROM_START;
	_csx_soc_init_load_rgn_file(csx, &csx->loader, LOADER_FileName);

//	loader_firmware = 1;

	if(loader_firmware) {
		csx->firmware.base = 0x10020000;
	} else {
		if(1) {
			csx->loader.base = 0x10020000;
			__csx_soc_init_cdp(csx, &csx->loader);

			csx->firmware.base = csx->loader.base + csx->loader.size;

//			csx->loader.base = EMIFS_CS0_RESERVED_BOOT_ROM_START;
		} else
			csx->firmware.base = 0x10020000;
	}

	_csx_soc_init_load_rgn_file(csx, &csx->firmware, FIRMWARE_FileName);

	csx_data_p cdp = loader_firmware ? &csx->firmware : &csx->loader;

	csx_soc_brom_init(csx->soc, cdp);

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

void csx_soc_reset(csx_p csx)
{
	if(_trace_atreset) {
		LOG();
	}

	_csx_soc_atreset(csx->soc);
}
