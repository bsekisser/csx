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

#include <SDL2/SDL.h>
#include <SDL2/SDL_timer.h>

typedef struct sdl_tag* sdl_ptr;
typedef sdl_ptr const sdl_ref;

struct sdl_tag {
	armvm_ptr armvm;
	csx_ptr csx;
	SDL_Event event;
	SDL_Renderer* renderer;
	SDL_Window* window;
}sdl;

void catch_sig_term(const int sign)
{
	printf("\n\n\n\nsignal caught, terminating.\n\n");

	sdl.csx->state = CSX_STATE_HALT;

	return;
	(void)sign;
}

int csx_soc_main(csx_ref csx, const int core_trace, const int loader_firmware)
{
	signal(SIGINT, catch_sig_term);
	signal(SIGTERM, catch_sig_term);

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

	err = (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0);
	if(err) {
		LOG("error initializing SDL: %s", SDL_GetError());
		goto sdl_fail_init;
	}

	if((err = !(sdl.window = SDL_CreateWindow("csx",
		SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
		640, 480, 0))))
	{
		LOG("error creating window: %s", SDL_GetError())
		goto sdl_fail_window;
	}

	if((err = !(sdl.renderer = SDL_CreateRenderer(sdl.window, -1, SDL_RENDERER_ACCELERATED))))
	{
		LOG("error creating renderer: %s", SDL_GetError());
		goto sdl_fail_renderer;
	}

	SDL_RenderPresent(sdl.renderer);

	if(!err)
	{
		csx->state = CSX_STATE_RUN;

		armvm_threaded_start(csx->armvm);

		const uint32_t frameBuffer_pat = 0x10fda7e0 - 0x10000000;
//		const uint32_t frameBuffer_pat = 0x10fda800 - 0x10000000;
		LOGx32(frameBuffer_pat);

		const uint32_t bytes = 32 + (2 * (240 * 320));
		LOGx32(bytes)

		LOGx32(frameBuffer_pat + bytes);

		const void *const framebuffer = csx->sdram + frameBuffer_pat;

		for(;(CSX_STATE_RUN & csx->state);) {
			if(CYCLE & 0x7fff) {
				for(unsigned y = 0; y < 240; y++) {
					const uint8_t *line = framebuffer + ((y * 320) << 1);

					for(unsigned x = 0; x < 320; x++) {
						const uint16_t pixel = le16toh(*line++);
						const uint8_t r = ((pixel >> 10) & 31) << 3;
						const uint8_t g = ((pixel >> 5) & 077) << 2;
						const uint8_t b = (pixel & 31) << 3;

						SDL_SetRenderDrawColor(sdl.renderer, r, g, b, 255);

						const unsigned xx = x << 1;
						const unsigned yy = y << 1;

						SDL_RenderDrawLine(sdl.renderer, xx, yy, xx + 1, yy + 1);
					}
				}

				SDL_RenderPresent(sdl.renderer);

				SDL_PollEvent(&sdl.event);
				switch (sdl.event.type) {
					case	SDL_QUIT:
						csx->state = CSX_STATE_HALT;
						break;
					case	SDL_KEYDOWN: {
						int scancode = sdl.event.key.keysym.scancode;
						if(/*0x1b*/ 0x09 == scancode)
							csx->state = CSX_STATE_HALT;
					} break;
				}
			}
		}
	}

	LOG("CYCLE = 0x%016" PRIx64 ", IP = 0x%08x, PC = 0x%08x", CYCLE, IP, PC);

	SDL_DestroyRenderer(sdl.renderer);
sdl_fail_renderer:
	SDL_DestroyWindow(sdl.window);
sdl_fail_window:
	SDL_Quit();
sdl_fail_init:
	return(err);
}
