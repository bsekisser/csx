#include "csx.h"
#include "csx_mmio.h"

#include "csx_mmio_omap.h"

#include "csx_mmio_ocp.h"

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

#include "csx_mmio_trace.h"

static uint32_t csx_mmio_ocp_read(void* data, uint32_t addr, uint8_t size)
{
	const csx_mmio_ocp_p ocp = data;
	const csx_p csx = ocp->csx;

	csx_mmio_trace(csx->mmio, trace_list, addr);

	uint32_t value;
	
	switch(addr & ~0xf)
	{
		case EMIFS_ADV_CS_CONFIG(0):
			value = ocp->emifs[addr & 0xc].adv_config;
			break;
		case EMIFS_CS_CONFIG(0):
			value = ocp->emifs[addr & 0xc].config;
			break;		
		default:
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
			break;
	}
	
//	return(csx_data_read((uint8_t*)&value, size));
	return(value);
}

static void csx_mmio_ocp_write(void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const csx_mmio_ocp_p ocp = data;
	const csx_p csx = ocp->csx;
	
	csx_mmio_trace(csx->mmio, trace_list, addr);

	switch(addr & ~0xf)
	{
		case EMIFS_ADV_CS_CONFIG(0):
		{
			LOG("BTMODE: %01u, ADVHOLD: %01u, OEHOLD: %01u, OESETUP: %01u",
				BEXT(value, 9), BEXT(value, 8), mlBFEXT(value, 7, 4), mlBFEXT(value, 3, 0));

			ocp->emifs[addr & 0xc].adv_config = value;
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
			
			ocp->emifs[addr & 0xc].config = value;
		}	break;		
		default:
			LOG("addr = 0x%08x, cs = 0x%02x", addr, addr & 0xc);
			LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
			break;	
	}
}

static void csx_mmio_ocp_reset(void* data)
{
	const csx_mmio_ocp_p ocp = data;

	for(int i = 0; i < 4; i++)
	{
		ocp->emifs[i].adv_config = 0x00000000;
		ocp->emifs[i].config = 0x00000000;
	}
}

static csx_mmio_peripheral_t ocp_peripheral = {
	.base = CSX_MMIO_OCP_BASE,

	.reset = csx_mmio_ocp_reset,

	.read = csx_mmio_ocp_read,
	.write = csx_mmio_ocp_write,
};

int csx_mmio_ocp_init(csx_p csx, csx_mmio_p mmio, csx_mmio_ocp_h h2ocp)
{
	csx_mmio_ocp_p ocp;
	
	ERR_NULL(ocp = malloc(sizeof(csx_mmio_ocp_t)));
	if(!ocp)
		return(-1);

	ocp->csx = csx;
	ocp->mmio = mmio;
	
	*h2ocp = ocp;

	csx_mmio_peripheral(mmio, &ocp_peripheral, ocp);
	
	return(0);
}
