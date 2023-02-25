#include "soc_mmio_gp_timer.h"

#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define MMIO_GPTMR2_LIST \
	MMIO_TRACE_LIST_HEAD(2) \
	MMIO(0xfffb, 0x1c10, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TIOCP_CFG) \
	MMIO(0xfffb, 0x1c18, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TISR) \
	MMIO(0xfffb, 0x1c1c, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TIER) \
	MMIO(0xfffb, 0x1c20, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TWER) \
	MMIO(0xfffb, 0x1c24, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TCLR) \
	MMIO(0xfffb, 0x1c2c, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TLDR) \
	MMIO(0xfffb, 0x1c38, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TMAR) \
	MMIO(0xfffb, 0x1c40, 0x0000, 0x0000, 32, MEM_RW, GPTMR2_TSICR) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_GPTMR3_LIST \
	MMIO_TRACE_LIST_HEAD(3) \
	MMIO(0xfffb, 0x2410, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TIOCP_CFG) \
	MMIO(0xfffb, 0x2418, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TISR) \
	MMIO(0xfffb, 0x241c, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TIER) \
	MMIO(0xfffb, 0x2420, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TWER) \
	MMIO(0xfffb, 0x2424, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TCLR) \
	MMIO(0xfffb, 0x242c, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TLDR) \
	MMIO(0xfffb, 0x2438, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TMAR) \
	MMIO(0xfffb, 0x2440, 0x0000, 0x0000, 32, MEM_RW, GPTMR3_TSICR) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_GPTMR5_LIST \
	MMIO_TRACE_LIST_HEAD(5) \
	MMIO(0xfffb, 0x3410, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TIOCP_CFG) \
	MMIO(0xfffb, 0x3418, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TISR) \
	MMIO(0xfffb, 0x341c, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TIER) \
	MMIO(0xfffb, 0x3420, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TWER) \
	MMIO(0xfffb, 0x3424, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TCLR) \
	MMIO(0xfffb, 0x342c, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TLDR) \
	MMIO(0xfffb, 0x3438, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TMAR) \
	MMIO(0xfffb, 0x3440, 0x0000, 0x0000, 32, MEM_RW, GPTMR5_TSICR) \
	MMIO_TRACE_LIST_TAIL

#define MMIO_LIST \
	MMIO_GPTMR2_LIST \
	MMIO_GPTMR3_LIST \
	MMIO_GPTMR5_LIST

/*	1	=	14	--	0001 0(1xx xxxx xxxx)
 *	2	=	1c	--	0001 1(1xx xxxx xxxx)
 */

const char unit_map[16] = { 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0 };

#define GPTMR(_t, _o)			(CSX_MMIO_GP_TIMER(_t) + _o)

#define GPTMR_TIOCP_CFG		0x10
#define GPTMR_TISR			0x18
#define GPTMR_TIER			0x1c
#define GPTMR_TWER			0x20
#define GPTMR_TCLR			0x24
#define GPTMR_TLDR			0x2c
#define GPTMR_TMAR			0x38
#define GPTMR_TSICR			0x40

#include "soc_mmio_trace.h"

#include "soc_mmio_ea_trace_enum.h"
MMIO_ENUM_LIST

#include "soc_mmio_ea_trace_list.h"
MMIO_TRACE_LIST

static soc_mmio_peripheral_t gp_timer_peripheral[7] = {
	{
		.base = CSX_MMIO_GP_TIMER(1),
		.trace_list = 0 /*trace_list_1*/,

		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_GP_TIMER(2),
		.trace_list = trace_list_2,

		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_GP_TIMER(3),
		.trace_list = trace_list_3,

		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_GP_TIMER(4),
		.trace_list = 0 /*trace_list_4*/,
		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_GP_TIMER(5),
		.trace_list = trace_list_5,
		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_GP_TIMER(6),
		.trace_list = 0 /*trace_list_6*/,
		.reset = 0,

		.read = 0,
		.write = 0,
	}, {
		.base = CSX_MMIO_GP_TIMER(7),
		.trace_list = 0 /*trace_list_7*/,

		.reset = 0,

		.read = 0,
		.write = 0,
	}
};

static int _gp_timer_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	soc_mmio_gp_timer_h h2gpt = param;
	soc_mmio_gp_timer_p gpt = *h2gpt;

	free(gpt);
	*h2gpt = 0;

	return(0);
}

int soc_mmio_gp_timer_init(csx_p csx, soc_mmio_p mmio, soc_mmio_gp_timer_h h2gpt)
{
	// TODO: csx_mmio, csx_mem
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2gpt);
	
	if(_trace_init) {
		LOG();
	}

	soc_mmio_gp_timer_p gpt = calloc(1, sizeof(soc_mmio_gp_timer_t));
	ERR_NULL(gpt);

	gpt->csx = csx;
	gpt->mmio = mmio;

	*h2gpt = gpt;

	soc_mmio_callback_atexit(mmio, _gp_timer_atexit, h2gpt);

	for(int i = 1; i <= 7; i++)
	{

		if(0) LOG("i = %02u, va = 0x%08x", i, CSX_MMIO_GP_TIMER(i));
		soc_mmio_peripheral(mmio, &gp_timer_peripheral[i - 1], gpt);
	}

	return(0);
}
