#include "csx_sdl.h"
#include "csx.h"

/* **** */

#include "csx_sdram.h"
#include "csx_soc_sram.h"

/* **** */

#include "libbse/include/log.h"
#include "libbse/include/shift_roll.h"

/* **** */

#include <SDL2/SDL.h>
#include <SDL2/SDL_timer.h>

/* **** */

static const unsigned height = 200;
static const unsigned width = 320;

/* **** */

typedef struct point_tag* point_ptr;
typedef point_ptr const point_ref;

typedef struct point_tag {
	unsigned x;
	unsigned y;
}point_t;

typedef struct rect_tag* rect_ptr;
typedef rect_ptr const rect_ref;

typedef struct rect_tag {
	point_t at;
	point_t extent;
}rect_t;

typedef struct sdl_tag* sdl_ptr;
typedef sdl_ptr const sdl_ref;

struct sdl_tag {
	armvm_ptr armvm;
	csx_ptr csx;
	SDL_Event event;
	rect_t frame;
	void* framebuffer;
	SDL_Renderer* renderer;
	struct {
		int fb;
		point_t frame;
		int ppos;
	}skew;
	struct {
		unsigned hw:1;
		unsigned xy:1;
	}swap;
	SDL_Window* window;
}sdl;

/* **** */

static
void _catch_sig_term(const int sign)
{
	printf("\n\n\n\nsignal caught, terminating.\n\n");

	sdl.csx->state = CSX_STATE_HALT;

	return;
	(void)sign;
}

static
void _save(csx_ref csx)
{
	LOG();

	if(1 == csx_action(0, csx, _ACTION_PAUSE)) {
		for(;;) {
			const int rval = csx_action(0, csx, _ACTION_PAUSE_CHECK);
			if(0 > rval)
				return;

			if(1 == rval)
				break;
		}
	}

	LOG_ACTION(csx_sdram_save(csx));
	LOG_ACTION(csx_soc_sram_save(csx->soc));

	csx_action(0, csx, _ACTION_RESUME);
}

static
unsigned _xsr(const unsigned data, int *const offset, const unsigned bits, const unsigned lsr_bits)
{
	const int ooffset = *offset;
	*offset += bits;

	const unsigned mask = (1 << bits) - 1;
	const unsigned data_shifted = (0 > ooffset)
		? _rol(data, -ooffset)
		: _ror(data, ooffset);

	return((data_shifted & mask) << lsr_bits);
}

/* **** */

int csx_sdl_exit(csx_ref csx)
{
	if(sdl.renderer)
		SDL_DestroyRenderer(sdl.renderer);

	if(sdl.window)
		SDL_DestroyWindow(sdl.window);

	SDL_Quit();

	return(-1);
}

void csx_sdl_event(csx_ref csx)
{
	SDL_PollEvent(&sdl.event);
	switch (sdl.event.type) {
		case	SDL_QUIT:
			csx->state = CSX_STATE_HALT;
			break;
		case	SDL_KEYDOWN: {
			int scancode = sdl.event.key.keysym.scancode;
			switch(scancode) {
				case 0x48: // pause/break
					csx->state = CSX_STATE_HALT;
					break;

				case 0x13: {
					const int rval = csx_action(0, csx, _ACTION_PAUSE_CHECK);
					if(0 > rval)
						break;
					else if(0 == rval)
						LOG_ACTION(csx_action(0, csx, _ACTION_PAUSE));
				}	break;

				case 0x16: _save(csx); break;

				case 0x1e: break;

				case 0x59: sdl.skew.fb--; break;
				case 0x5b: sdl.skew.fb++; break;

				case 0x5e: sdl.skew.frame.x--; break;
				case 0x5c: sdl.skew.frame.x++; break;

				case 0x5a: sdl.skew.frame.y--; break;
				case 0x60: sdl.skew.frame.y++; break;

				case 0x5f: sdl.skew.ppos--; break;
				case 0x61: sdl.skew.ppos++; break;

				case 0x54:
					sdl.swap.xy = !!(!sdl.swap.xy);
					break;
				case 0x55:
					sdl.swap.hw = !!(!sdl.swap.hw);
					break;

				default:
					LOGx32(scancode);
					break;
			}

			LOG("skew-(fb: 0x%08x, frame-(x: 0x%08x, y: 0x%08x), ppos: 0x%08x), swap-(hw: %u, xy: %u)\n",
				sdl.skew.fb, sdl.skew.frame.x, sdl.skew.frame.y, sdl.skew.ppos, sdl.swap.hw, sdl.swap.xy);
		}	break;
	}
}

int csx_sdl_init(csx_ref csx)
{
	signal(SIGINT, _catch_sig_term);
	signal(SIGTERM, _catch_sig_term);

	int err = (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0);
	if(err) {
		LOG("error initializing SDL: %s", SDL_GetError());
		return(csx_sdl_exit(csx));
	}

	point_ref extent = &sdl.frame.extent;

	extent->x = width << 1;
	extent->y = height << 1;

	if((err = !(sdl.window = SDL_CreateWindow("csx",
		SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
		extent->x, extent->y, 0))))
	{
		LOG("error creating window: %s", SDL_GetError())
		return(csx_sdl_exit(csx));
	}

	if((err = !(sdl.renderer = SDL_CreateRenderer(sdl.window, -1, SDL_RENDERER_ACCELERATED))))
	{
		LOG("error creating renderer: %s", SDL_GetError());
		return(csx_sdl_exit(csx));
	}

	SDL_RenderPresent(sdl.renderer);

	point_ref at = &sdl.frame.at;

	at->x = ((extent->x >> 1) - (width >> 1)) >> 1;
	at->y = ((extent->y >> 1) - (height >> 1)) >> 1;

	const uint32_t bytes = (2 * (240 * 320)) /* + 32 */;
	LOGx32(bytes)

	const uint32_t frameBuffer_pat = 0x01000000 - bytes;
	LOGx32(frameBuffer_pat);

	LOGx32(frameBuffer_pat + bytes);

	sdl.framebuffer = *csx->sdram + frameBuffer_pat;

	sdl.skew.fb = 0;
	sdl.skew.frame.x = 0;
	sdl.skew.frame.y = 0;
	sdl.skew.ppos = 0;
	sdl.swap.hw = 0;
	sdl.swap.xy = 1;

	return(err);
}

void csx_sdl_step(csx_ref csx) {
	SDL_SetRenderDrawColor(sdl.renderer, 0, 0, 0, 255);
	SDL_RenderClear(sdl.renderer);

	point_ref at = &sdl.frame.at;
	point_ref extent = &sdl.frame.extent;

	void *const fb = sdl.framebuffer + sdl.skew.fb;

	const unsigned height0 = height + sdl.skew.frame.y;
	const unsigned width0 = width + sdl.skew.frame.x;

	const unsigned swap_hw = sdl.swap.hw;

	const unsigned hheight = swap_hw ? width0 : height0;
	const unsigned wwidth = swap_hw ? height0 : width0;

	const unsigned swap_xy = sdl.swap.xy;

	for(unsigned y = 0; y < hheight; y++) {
		void* line = fb + (swap_xy ? (y << 1) : (y * hheight));

		for(unsigned x = 0; x < wwidth; x++) {
			const unsigned xx = at->x + x;
			const unsigned yy = at->y + y;

			const unsigned pixel = *(unsigned*)line;
			line += (swap_xy ? wwidth : (x << 1));

			int ppos = sdl.skew.ppos;

			const uint8_t b = _xsr(pixel, &ppos, 5, 3);
			const uint8_t g = _xsr(pixel, &ppos, 6, 2);
			const uint8_t r = _xsr(pixel, &ppos, 5, 3);

			SDL_SetRenderDrawColor(sdl.renderer, r, g, b, 255);
			SDL_RenderDrawLine(sdl.renderer, xx, yy, xx, yy);
		}
	}

	SDL_RenderPresent(sdl.renderer);

	csx_sdl_event(csx);
}
