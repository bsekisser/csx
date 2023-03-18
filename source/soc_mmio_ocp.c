#include "soc_mmio_ocp.h"

#include "csx_data.h"
#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define _OCP(_x)				(CSX_MMIO_OCP_BASE + (_x))

#define EMIFS_CS_CONFIG(_x)			_OCP(0x10 + (((_x) & 3) << 2))
#define EMIFS_ADV_CS_CONFIG(_x)		_OCP(0x50 + (((_x) & 3) << 2))

#define MMIO_LIST \
	MMIO(0xfffe, 0xcc00, 0x0000, 0x0000, 32, MEM_RW, OCP_TI_PRIO) \
	MMIO(0xfffe, 0xcc14, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS1_CONFIG) \
	MMIO(0xfffe, 0xcc18, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS2_CONFIG) \
	MMIO(0xfffe, 0xcc1c, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS3_CONFIG) \
	MMIO(0xfffe, 0xcc20, 0x0061, 0x8800, 32, MEM_RW, EMIFF_SDRAM_CONFIG) \
	MMIO(0xfffe, 0xcc50, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS0_CONFIG) \
	MMIO(0xfffe, 0xcc54, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS1_CONFIG) \
	MMIO(0xfffe, 0xcc58, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS2_CONFIG) \
	MMIO(0xfffe, 0xcc5c, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS3_CONFIG)

#define TRACE_LIST
#include "soc_mmio_trace.h"
#undef TRACE_LIST

static void soc_mmio_ocp_write(void* param, void* data, uint32_t addr, size_t size, uint32_t value)
{
	if(0) LOG("param = 0x%08" PRIxPTR ", data = 0x%08" PRIxPTR ", va = 0x%08x, value = 0x%08x, size 0x%02zx",
		(uintptr_t)param, (uintptr_t)data, addr, value, size);

	const soc_mmio_ocp_p ocp = param;
	const csx_p csx = ocp->csx;

	const ea_trace_p eat = soc_mmio_trace(csx->mmio, 0, addr);
	if(eat)
	{
		switch(addr)
		{
			case EMIFF_SDRAM_CONFIG:
				LOG_START("SBZ: %01u", mlBFEXT(value, 31, 30));
				_LOG_(" LG SDRAM: %01u", mlBFEXT(value, 29, 28));
				_LOG_(" CLK: %01u", BEXT(value, 27));
				_LOG_(" PWD: %01u", BEXT(value, 26));
				_LOG_(" SDRAM FRQ: %01u", mlBFEXT(value, 25, 24));
				_LOG_(" ARCV: x%05u", mlBFEXT(value, 23, 8));
				_LOG_(" SDRAM Type: %01u", mlBFEXT(value, 7, 4));
				_LOG_(" ARE: %01u", mlBFEXT(value, 3, 2));
				_LOG_(" SBO: %01u", BEXT(value, 1));
				LOG_END(" Slrf: %01u", BEXT(value, 0));
				LOG_ACTION(exit(-1));
				break;
			case EMIFS_ADV_CS_CONFIG(0):
			case EMIFS_ADV_CS_CONFIG(1):
			case EMIFS_ADV_CS_CONFIG(2):
			case EMIFS_ADV_CS_CONFIG(3):
			{
				LOG("BTMODE: %01u, ADVHOLD: %01u, OEHOLD: %01u, OESETUP: %01u",
					BEXT(value, 9), BEXT(value, 8), mlBFEXT(value, 7, 4), mlBFEXT(value, 3, 0));
			}	break;
			case EMIFS_CS_CONFIG(1):
			case EMIFS_CS_CONFIG(2):
			case EMIFS_CS_CONFIG(3):
			{
				LOG("PGWSTEN: %01u, PGWST: %01u, BTWST: %01u, MAD: %01u, BW: %01u",
					BEXT(value, 31), mlBFEXT(value, 30, 27),
					mlBFEXT(value, 26, 23), BEXT(value, 22), BEXT(value, 20));

				const uint rdmode = mlBFEXT(value, 18, 16);
				LOG("RDMODE: %01u, PGWST/WELEN: %01u, WRWST: %01u, RDWST: %01u",
					rdmode, mlBFEXT(value, 15, 12), mlBFEXT(value, 11, 8), mlBFEXT(value, 7, 4));

				const char *rdmodesl[] = {
					"0x000, Mode 0: Asyncronous read",
					"0x001, Mode 1: Page mode ROM read - 4 words per page",
					"0x010, Mode 2: Page mode ROM read - 8 words per page",
					"0x011, Mode 3: Page mode ROM read - 16 words per page",
					"0x100, Mode 4: Syncronous burst read mode",
					"0x101, Mode 5: Syncronous burst read mode",
					"0x110, Reserved for future expansion",
					"0x111, Mode 7: Syncronous burst read mode"};

				LOG("%s", rdmodesl[rdmode & 0x07]);

				LOG("RT: %01u, FCLKDIV: %01u", BEXT(value, 2), mlBFEXT(value, 1, 0));
			}	break;
		}

		csx_data_offset_write(data, (addr & 0xff), size, value);
	} else {
		LOG("addr = 0x%08x, cs = 0x%02x", addr, addr & 0xc);
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

static soc_mmio_peripheral_t ocp_peripheral = {
	.base = CSX_MMIO_OCP_BASE,
	.trace_list = trace_list,

	.reset = 0,

	.read = 0,
	.write = soc_mmio_ocp_write,
};

static int _ocp_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_mmio_ocp_h h2ocp = param;
//	soc_mmio_ocp_p ocp = *h2ocp;

	handle_free(param);

	return(0);
}

int soc_mmio_ocp_init(csx_p csx, soc_mmio_p mmio, soc_mmio_ocp_h h2ocp)
{
	// TODO: csx_mmio, csx_mem
	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2ocp);

	if(_trace_atexit) {
		LOG();
	}

	soc_mmio_ocp_p ocp = HANDLE_CALLOC(h2ocp, 1, sizeof(soc_mmio_ocp_t));
	ERR_NULL(ocp);

	ocp->csx = csx;
	ocp->mmio = mmio;

	soc_mmio_callback_atexit(mmio, _ocp_atexit, h2ocp);

	soc_mmio_peripheral(mmio, &ocp_peripheral, ocp);

	return(0);
}
