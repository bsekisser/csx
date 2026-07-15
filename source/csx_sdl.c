#include "csx_sdl.h"
#include "csx.h"

/* **** */

#include "csx_sdram.h"
#include "csx_soc_sram.h"

/* **** */

#include "git/libbse/include/bitop_macros.h"
#include "libbse/include/log.h"
#include "libbse/include/shift_roll.h"

/* **** */

#include <endian.h>

#include <SDL2/SDL.h>
#include <SDL2/SDL_timer.h>

/* **** */

static const unsigned height = 240;
static const unsigned width = 320;

#define SWAP(a,b) ({ typeof(a) tmp = a; a = b, b = tmp; })

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
	libarmvm_ptr armvm;
	unsigned bpp;
	point_t center;
	csx_ptr csx;
	SDL_Event event;
	rect_t frame;
	void* framebuffer;
	SDL_Renderer* renderer;
	point_t screen;
	struct {
		int fb;
		point_t frame;
		int ppos;
	}skew;
	struct {
		struct {
			char hw:1;
			char xy:1;
		}swap;
		char dbl:1;
	}flags;
	SDL_Window* window;
}sdl;

/* **** */

static
void _catch_sig_term(const int sign)
{
	printf("\n\n\n\nsignal caught, terminating.\n\n");

	sdl.csx->state.halt = 1;

	return;
	(void)sign;
}

static
void _reconfigure(void)
{
	rect_ref frame = &sdl.frame;

	point_ref at  = &frame->at;
	point_ref center = &sdl.center;
	point_ref extent = &frame->extent;
	const point_ref screen = &sdl.screen;

	center->x = screen->x >> 1;
	center->y = screen->y >> 1;
	LOG("screen(x: %u, y: %u)", screen->x, screen->y);

	const unsigned hheight = height + sdl.skew.frame.y;
	const unsigned wwidth = width + sdl.skew.frame.x;

	at->x = sdl.flags.dbl ? 0 : center->x - (wwidth >> 1);
	at->y = sdl.flags.dbl ? 0 : center->y - (hheight >> 1);

	extent->x = sdl.flags.dbl ? wwidth : center->x + (wwidth >> 1);
	extent->y = sdl.flags.dbl ? hheight : center->y + (hheight >> 1);

	if(sdl.flags.swap.hw) {
		SWAP(at->x, at->y);
		SWAP(center->x, center->y);
		SWAP(extent->x, extent->y);
	}

	LOG("at(x: %u, y: %u), center(x: %u, y: %u), extent(x: %u, y: %u)",
		at->x, at->y, center->x, center->y, extent->x, extent->y);
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

static __attribute__((warn_unused_result))
unsigned _xsr(const unsigned data, int *const offset, const unsigned bits, const unsigned lsr_bits)
{
	const int ooffset = *offset;
	*offset += bits;

	const unsigned mask = (1 << bits) - 1;
	const unsigned data_shifted = (0 > ooffset)
		? _ROL_MASKED(data, -ooffset)
		: _ROR(data, ooffset);

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
	UNUSED(csx);
}

void csx_sdl_event(csx_ref csx)
{
	SDL_PollEvent(&sdl.event);
	switch (sdl.event.type) {
		case	SDL_QUIT:
			csx->state.halt = 1;
			break;
		case	SDL_KEYDOWN: {
			int scancode = sdl.event.key.keysym.scancode;
			switch(scancode) {
				case 0x48: // pause/break
					csx->state.exit = csx->state.halt;
					csx->state.halt = 1;
					break;

				case 0x13: // control-p
				{
					const int rval = csx_action(0, csx, _ACTION_PAUSE_CHECK);
					if(0 > rval)
						break;
					else if(0 == rval)
						LOG_ACTION(csx_action(0, csx, _ACTION_PAUSE));
				}	break;

				case 0x16: // control-s
					_save(csx); break;

//				case 0x1e: break; // 1

//				case 0x35: break; // ~`

				case 0x59: // keypad -- 1/end
					sdl.skew.fb--;
					break;
				case 0x5b: // keypad -- 3/page-down
					sdl.skew.fb++;
					break;

				case 0x5e: // keypad -- 4/left
					sdl.skew.frame.x--;
					break;
				case 0x5c: // keypad -- 6/right
					sdl.skew.frame.x++;
					break;

				case 0x5a: // keypad -- 2/down
					sdl.skew.frame.y++;
					break;

				case 0x60: // keypad -- 8/up
					sdl.skew.frame.y--;
					break;

				case 0x5f: // keypad -- 7/home
					sdl.skew.ppos--;
					break;
				case 0x61: // keypad -- 9/page-up
					sdl.skew.ppos++;
					break;

				case 0x54: // keypad -- /
					sdl.flags.swap.xy = !sdl.flags.swap.xy;
					break;
				case 0x55: // keypad -- *
					sdl.flags.swap.hw = !sdl.flags.swap.hw;
					break;

				default:
					LOGx32(scancode);
					break;
			}

			_reconfigure();

			LOG("skew-(fb: 0x%08x, frame-(x: 0x%08x, y: 0x%08x), ppos: 0x%08x), swap-(hw: %u, xy: %u)\n",
				sdl.skew.fb, sdl.skew.frame.x, sdl.skew.frame.y, sdl.skew.ppos, sdl.flags.swap.hw, sdl.flags.swap.xy);
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

	point_ref screen = &sdl.screen;

	screen->x = width << 1;
	screen->y = height << 1;

	if((err = !(sdl.window = SDL_CreateWindow("csx",
		SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
		screen->x, screen->y, 0))))
	{
		LOG("error creating window: %s", SDL_GetError());
		return(csx_sdl_exit(csx));
	}

	if((err = !(sdl.renderer = SDL_CreateRenderer(sdl.window, -1, SDL_RENDERER_ACCELERATED))))
	{
		LOG("error creating renderer: %s", SDL_GetError());
		return(csx_sdl_exit(csx));
	}

	SDL_RenderPresent(sdl.renderer);

	const uint32_t bytes = ((height * width) << 1) /* + 32 */;
	LOGx32(bytes);

	const uint32_t frameBuffer_pat = 0x01000000 - bytes;
	LOGx32(frameBuffer_pat);

	LOGx32(frameBuffer_pat + bytes);

	sdl.framebuffer = *csx->sdram + frameBuffer_pat;

	sdl.bpp = 2;
	sdl.skew.fb = 0;
	sdl.skew.frame.x = 0;
	sdl.skew.frame.y = 0;
	sdl.skew.ppos = 0;
	sdl.flags.dbl = 1;
	sdl.flags.swap.hw = 1;
	sdl.flags.swap.xy = 1;

	_reconfigure();

	return(err);
}

void csx_sdl_step(csx_ref csx) {
	SDL_SetRenderDrawColor(sdl.renderer, 0, 0, 0, SDL_ALPHA_OPAQUE);
	SDL_RenderClear(sdl.renderer);

	point_ref at = &sdl.frame.at;
	point_ref center = &sdl.center;
	point_ref extent = &sdl.frame.extent;

	void *fb = sdl.framebuffer + sdl.skew.fb;

	for(unsigned y = at->y; y < extent->y; y++) {
		for(unsigned x = at->x; x < extent->x; x++) {
			unsigned pixel = 0;

			switch(sdl.bpp) {
				case 2: pixel = le16toh(*(unsigned short*)fb); break;
				default: pixel = le32toh(*(unsigned*)fb); break;
			}
			fb += 2;

			signed ppos = sdl.skew.ppos;
			const uint8_t b = _xsr(pixel, &ppos, 5, 3);
			const uint8_t g = _xsr(pixel, &ppos, 6, 2);
			const uint8_t r = _xsr(pixel, &ppos, 5, 3);

			SDL_SetRenderDrawColor(sdl.renderer, r, g, b, SDL_ALPHA_OPAQUE);

			const unsigned xx = x << sdl.flags.dbl;
			const unsigned yy = y << sdl.flags.dbl;

			if(sdl.flags.swap.xy)
				SDL_RenderDrawLine(sdl.renderer, yy, xx, yy, xx);
			else
				SDL_RenderDrawLine(sdl.renderer, xx, yy, xx, yy);
		}
	}

	SDL_RenderPresent(sdl.renderer);

	csx_sdl_event(csx);
}
