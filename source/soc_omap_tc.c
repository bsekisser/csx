#include "soc_omap_tc.h"

/* **** */

#include "csx_data.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_tc_t {
	csx_p			csx;
	csx_mmio_p		mmio;
	
	struct {
		uint32_t sdram_config;
	}emiff;
	struct {
		uint32_t adv_cs_config[4];
		uint32_t cs_config[4];
	}emifs;
	struct {
		struct {
			uint32_t prio;
		}t1;
		struct {}t2;
	}ocp;
}soc_omap_tc_t;

/* **** */

#define SOC_OMAP_TC_EMIFF_ACL(_MMIO) \
	_MMIO(0xfffe, 0xcc20, 0x0061, 0x8800, EMIFF_SDRAM_CONFIG, soc_omap_tc_emiff_sdram_config)

#define SOC_OMAP_TC_EMIFS_ACL(_MMIO) \
	_MMIO(0xfffe, 0xcc14, 0x0000, 0x0000, EMIFS_CS1_CONFIG, soc_omap_tc_emifs_cs_config) \
	_MMIO(0xfffe, 0xcc18, 0x0000, 0x0000, EMIFS_CS2_CONFIG, soc_omap_tc_emifs_cs_config) \
	_MMIO(0xfffe, 0xcc1c, 0x0000, 0x0000, EMIFS_CS3_CONFIG, soc_omap_tc_emifs_cs_config) \
	_MMIO(0xfffe, 0xcc50, 0x0000, 0x0000, EMIFS_ADV_CS0_CONFIG, soc_omap_tc_emifs_adv_cs_config) \
	_MMIO(0xfffe, 0xcc54, 0x0000, 0x0000, EMIFS_ADV_CS1_CONFIG, soc_omap_tc_emifs_adv_cs_config) \
	_MMIO(0xfffe, 0xcc58, 0x0000, 0x0000, EMIFS_ADV_CS2_CONFIG, soc_omap_tc_emifs_adv_cs_config) \
	_MMIO(0xfffe, 0xcc5c, 0x0000, 0x0000, EMIFS_ADV_CS3_CONFIG, soc_omap_tc_emifs_adv_cs_config)

#define SOC_OMAP_TC_OCP_T1_ACL(_MMIO) \
	_MMIO(0xfffe, 0xcc00, 0x0000, 0x0000, OCP_T1_PRIO, soc_omap_tc_ocp_t1_prio)

enum {
	SOC_OMAP_TC_EMIFF_ACL(MMIO_ENUM)
	SOC_OMAP_TC_EMIFS_ACL(MMIO_ENUM)
	SOC_OMAP_TC_OCP_T1_ACL(MMIO_ENUM)
};

/* **** */

static int _soc_omap_tc_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_omap_tc_h h2tc = param;
//	soc_omap_tc_p tc = *h2tc;

	handle_free(param);

	return(0);
}

static int _soc_omap_tc_atreset(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	const soc_omap_tc_p tc = param;

	tc->emiff.sdram_config = 0x00618800;

	return(0);
}

/* **** */

static uint32_t soc_omap_tc_emiff_sdram_config(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_tc_p tc = param;

	uint32_t data = write ? *write : 0;
//	const uint8_t offset = ppa & 0xff;

	if(write) {
		if(_trace_mmio_tc_emiff) {
			CSX_MMIO_TRACE_WRITE(tc->csx, ppa, size, data);
			LOG_START("SBZ: %01u", mlBFEXT(data, 31, 30));
			_LOG_(" LG SDRAM: %01u", mlBFEXT(data, 29, 28));
			_LOG_(" CLK: %01u", BEXT(data, 27));
			_LOG_(" PWD: %01u", BEXT(data, 26));
			_LOG_(" SDRAM FRQ: %01u", mlBFEXT(data, 25, 24));
			_LOG_(" ARCV: x%05u", mlBFEXT(data, 23, 8));
			_LOG_(" SDRAM Type: %01u", mlBFEXT(data, 7, 4));
			_LOG_(" ARE: %01u", mlBFEXT(data, 3, 2));
			_LOG_(" SBO: %01u", BEXT(data, 1));
			LOG_END(" Slrf: %01u", BEXT(data, 0));
		}
		tc->emiff.sdram_config = data;
	} else
		return(tc->emiff.sdram_config);

	return(0);
}

static uint32_t soc_omap_tc_emifs_adv_cs_config(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_tc_p tc = param;

	uint32_t data = write ? *write : 0;
	const uint8_t offset = ppa & 0xff;

	uint32_t* adv_cs_config = &tc->emifs.adv_cs_config[(offset >> 2) & 3];

	if(write) {
		if(_trace_mmio_tc_emifs) {
			CSX_MMIO_TRACE_WRITE(tc->csx, ppa, size, data);
			LOG_START("BTMODE: %01u", BEXT(data, 9));
			_LOG_(", ADVHOLD: %01u", BEXT(data, 8));
			_LOG_(", OEHOLD: %01u", mlBFEXT(data, 7, 4));
			LOG_END(", OESETUP: %01u", mlBFEXT(data, 3, 0));
		}
		*adv_cs_config = data;
	} else
		return(*adv_cs_config);

	return(0);
}

static uint32_t soc_omap_tc_emifs_cs_config(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_tc_p tc = param;

	uint32_t data = write ? *write : 0;
	const uint8_t offset = ppa & 0xff;

	uint32_t* cs_config = &tc->emifs.cs_config[(offset >> 2) & 3];

	if(write) {
		if(_trace_mmio_tc_emifs) {
			CSX_MMIO_TRACE_WRITE(tc->csx, ppa, size, data);
			LOG_START("PGWSTEN: %01u", BEXT(data, 31));
			_LOG_(", PGWST: %01u", mlBFEXT(data, 30, 27));
			_LOG_(", BTWST: %01u", mlBFEXT(data, 26, 23));
			_LOG_(", MAD: %01u", BEXT(data, 22));
			const unsigned bw = BEXT(data, 20);
			LOG_END(", BW: %01u (data bus width, %s bit)", bw, bw ? "32" : "16");

			const char *rdmodesl[] = {
				"0x000, Mode 0: Asyncronous read",
				"0x001, Mode 1: Page mode ROM read - 4 words per page",
				"0x010, Mode 2: Page mode ROM read - 8 words per page",
				"0x011, Mode 3: Page mode ROM read - 16 words per page",
				"0x100, Mode 4: Syncronous burst read mode",
				"0x101, Mode 5: Syncronous burst read mode",
				"0x110, Reserved for future expansion",
				"0x111, Mode 7: Syncronous burst read mode"};

			const unsigned rdmode = mlBFEXT(data, 18, 16);
			LOG("RDMODE: %01u -- %s", rdmode, rdmodesl[rdmode & 7]);
			LOG_START("PGWST/WELEN: %01u", mlBFEXT(data, 15, 12));
			_LOG_(", WRWST: %01u", mlBFEXT(data, 11, 8));
			_LOG_(", RDWST: %01u", mlBFEXT(data, 7, 4));
			_LOG_(", RT: %01u", BEXT(data, 2));
			LOG_END(", FCLKDIV: %01u", mlBFEXT(data, 1, 0));
		}
		*cs_config = data;
	} else
		return(*cs_config);

	return(0);
}

static uint32_t soc_omap_tc_ocp_t1_prio(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_tc_p tc = param;

	uint32_t data = write ? *write : 0;
//	const uint8_t offset = ppa & 0xff;

	if(write) {
		if(_trace_mmio_tc_emifs) {
			CSX_MMIO_TRACE_WRITE(tc->csx, ppa, size, data);
			LOG_START("OCP_PRIORITY: %01u", mlBFEXT(data, 15, 12));
			_LOG_(", DMA_PRIORITY: %01u", mlBFEXT(data, 11, 8));
			_LOG_(", DSP_PRIORITY: %01u", mlBFEXT(data, 6, 4));
			LOG_END(", ARM_PRIORITY: %01u", mlBFEXT(data, 2, 0));
		}
		tc->ocp.t1.prio = data;
	} else
		return(tc->ocp.t1.prio);

	return(0);
}

/* **** */

static csx_mmio_access_list_t _soc_omap_tc_acl[] = {
	SOC_OMAP_TC_EMIFF_ACL(MMIO_TRACE_FN)
	SOC_OMAP_TC_EMIFS_ACL(MMIO_TRACE_FN)
	SOC_OMAP_TC_OCP_T1_ACL(MMIO_TRACE_FN)
	{ .ppa = ~0U, },
};

int soc_omap_tc_init(csx_p csx, csx_mmio_p mmio, soc_omap_tc_h h2tc)
{
	if(_trace_atexit) {
		LOG();
	}

	assert(0 != csx);
	assert(0 != mmio);
	assert(0 != h2tc);

	/* ****/

	soc_omap_tc_p tc = handle_calloc((void**)h2tc, 1, sizeof(soc_omap_tc_t));
	ERR_NULL(tc);

	tc->csx = csx;
	tc->mmio = mmio;

	csx_mmio_callback_atexit(mmio, _soc_omap_tc_atexit, h2tc);
	csx_mmio_callback_atreset(mmio, _soc_omap_tc_atreset, tc);

	csx_mmio_register_access_list(mmio, 0, _soc_omap_tc_acl, tc);

	return(0);
}
