#include "soc_omap_tc.h"

/* **** */

#include "csx_data.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/callback_qlist.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"
#include "libbse/include/mem_access.h" // TODO

/* **** */

#include <errno.h>
#include <string.h>

/* **** */

typedef struct soc_omap_tc_tag {
	csx_ptr csx;
	csx_mmio_ptr mmio;

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

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
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

static int _soc_omap_tc_atexit(void *const param)
{
	ACTION_LOG(exit);

//	soc_omap_tc_href h2tc = param;
//	soc_omap_tc_ref tc = *h2tc;

	handle_ptrfree(param);

	return(0);
}

static int _soc_omap_tc_atreset(void *const param)
{
	ACTION_LOG(reset);

	soc_omap_tc_ref tc = param;

	tc->emiff.sdram_config = 0x00618800;

	return(0);
}

/* **** */

static uint32_t soc_omap_tc_emiff_sdram_config(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_tc_ref tc = param;
	csx_ref csx = tc->csx;

	uint32_t data = write ? *write : 0;
//	const uint8_t offset = ppa & 0xff;

	if(write) {
		if(_trace_mmio_tc_emiff) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
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

static uint32_t soc_omap_tc_emifs_adv_cs_config(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_tc_ref tc = param;
	csx_ref csx = tc->csx;

	uint32_t data = write ? *write : 0;
	const uint8_t offset = ppa & 0xff;

	uint32_t* adv_cs_config = &tc->emifs.adv_cs_config[(offset >> 2) & 3];

	if(write) {
		if(_trace_mmio_tc_emifs) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
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

static uint32_t soc_omap_tc_emifs_cs_config(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_tc_ref tc = param;
	csx_ref csx = tc->csx;

	uint32_t data = write ? *write : 0;
	const uint8_t offset = ppa & 0xff;

	uint32_t* cs_config = &tc->emifs.cs_config[(offset >> 2) & 3];

	if(write) {
		if(_trace_mmio_tc_emifs) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
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

static uint32_t soc_omap_tc_ocp_t1_prio(void *const param, const uint32_t ppa, const size_t size, uint32_t *const write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	soc_omap_tc_ref tc = param;
	csx_ref csx = tc->csx;

	uint32_t data = write ? *write : 0;
//	const uint8_t offset = ppa & 0xff;

	if(write) {
		if(_trace_mmio_tc_emifs) {
			CSX_MMIO_TRACE_WRITE(csx, ppa, size, data);
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

soc_omap_tc_ptr soc_omap_tc_alloc(csx_ref csx, csx_mmio_ref mmio, soc_omap_tc_href h2tc)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2tc);

	ACTION_LOG(alloc);

	/* **** */

	soc_omap_tc_ref tc = handle_calloc(h2tc, 1, sizeof(soc_omap_tc_t));
	ERR_NULL(tc);

	tc->csx = csx;
	tc->mmio = mmio;

	/* **** */

	csx_mmio_callback_atexit(mmio, &tc->atexit, _soc_omap_tc_atexit, h2tc);
	csx_mmio_callback_atreset(mmio, &tc->atreset, _soc_omap_tc_atreset, tc);

	/* **** */

	return(tc);
}

void soc_omap_tc_init(soc_omap_tc_ref tc)
{
	ACTION_LOG(init);
	ERR_NULL(tc);

	/* **** */

	csx_mmio_register_access_list(tc->mmio, 0, _soc_omap_tc_acl, tc);
}
