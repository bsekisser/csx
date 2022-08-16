#include "soc_mmio_ocp.h"

#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

#define _OCP(_x)				(CSX_MMIO_OCP_BASE + (_x))

#define EMIFS_CS_CONFIG(_x)			_OCP(0x10 + (((_x) & 3) << 2))
#define EMIFS_ADV_CS_CONFIG(_x)		_OCP(0x50 + (((_x) & 3) << 2))

#define MMIO_LIST \
	MMIO(0xfffe, 0xcc14, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS1_CONFIG) \
	MMIO(0xfffe, 0xcc18, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS2_CONFIG) \
	MMIO(0xfffe, 0xcc1c, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS3_CONFIG) \
	MMIO(0xfffe, 0xcc50, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS0_CONFIG) \
	MMIO(0xfffe, 0xcc54, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS1_CONFIG) \
	MMIO(0xfffe, 0xcc58, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS2_CONFIG) \
	MMIO(0xfffe, 0xcc5c, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS3_CONFIG)

#define TRACE_LIST
	#include "soc_mmio_trace.h"
#undef TRACE_LIST

static void soc_mmio_ocp_write(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_ocp_p ocp = param;
	const csx_p csx = ocp->csx;
	
	ea_trace_p eat = soc_mmio_trace(csx->mmio, trace_list, addr);
	if(eat)
	{
		switch(addr & ~0xf)
		{
			case EMIFS_ADV_CS_CONFIG(0):
			{
				LOG("BTMODE: %01u, ADVHOLD: %01u, OEHOLD: %01u, OESETUP: %01u",
					BEXT(value, 9), BEXT(value, 8), mlBFEXT(value, 7, 4), mlBFEXT(value, 3, 0));
			}	break;
			case EMIFS_CS_CONFIG(0):
			{
				LOG("PGWSTEN: %01u, PGWST: %01u, BTWST: %01u, MAD: %01u, BW: %01u",
					BEXT(value, 31), mlBFEXT(value, 30, 27),
					mlBFEXT(value, 26, 23), BEXT(value, 22), BEXT(value, 20));
				
				int rdmode = mlBFEXT(value, 18, 16);
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

		soc_data_write(data + (addr & 0xff), value, size);
	} else {
		LOG("addr = 0x%08x, cs = 0x%02x", addr, addr & 0xc);
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

static soc_mmio_peripheral_t ocp_peripheral = {
	.base = CSX_MMIO_OCP_BASE,

//	.reset = soc_mmio_ocp_reset,

//	.read = soc_mmio_ocp_read,
	.write = soc_mmio_ocp_write,
};

int soc_mmio_ocp_init(csx_p csx, soc_mmio_p mmio, soc_mmio_ocp_h h2ocp)
{
	soc_mmio_ocp_p ocp;
	
	ERR_NULL(ocp = malloc(sizeof(soc_mmio_ocp_t)));
	if(!ocp)
		return(-1);

	ocp->csx = csx;
	ocp->mmio = mmio;
	
	*h2ocp = ocp;

	soc_mmio_peripheral(mmio, &ocp_peripheral, ocp);
	
	return(0);
}
