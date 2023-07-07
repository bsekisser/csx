#include "config.h"
#include "soc_omap_dma.h"

/* **** */

#include "csx_data.h"
#include "csx_mmio.h"

/* **** */

#include "bitfield.h"
#include "callback_qlist.h"
#include "handle.h"
#include "mem_access.h"

/* **** */

#define SOC_OMAP_DMA_CH_COUNT 16

typedef struct soc_omap_dma_ch_t* soc_omap_dma_ch_p;
typedef struct soc_omap_dma_ch_t {
		unsigned ccr;
		unsigned ccr2;
		unsigned cdac;
		unsigned cdei;
		unsigned cdfi;
		unsigned cdsa;
		unsigned cen;
		unsigned cfn;
		unsigned cicr;
		unsigned clnk_ctrl;
		unsigned color;
		unsigned csac;
		unsigned csdp;
		unsigned csei;
		unsigned csfi;
		unsigned csr;
		unsigned cssa;
		unsigned lch_ctrl;
}soc_omap_dma_ch_t;

typedef struct soc_omap_dma_lcd_t* soc_omap_dma_lcd_p;
typedef struct soc_omap_dma_lcd_t {
	unsigned csdp;
	unsigned ctrl;
	unsigned top_b[2];
}soc_omap_dma_lcd_t;

typedef struct soc_omap_dma_t {
	soc_omap_dma_ch_t ch[SOC_OMAP_DMA_CH_COUNT];
	soc_omap_dma_lcd_t lcd;

	struct {
		unsigned gcr;
		unsigned gscr;
	}gcr;

	csx_p csx;
	csx_mmio_p mmio;

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}soc_omap_dma_t;

/* **** */

enum {
	_GCR = 0x00,
	_GSCR = 0x04,
};

#define _DMA_GCRx(_x) (SOC_OMAP_DMA_GLOBAL + (_x))

#define DMA_GCR _DMA_GCRx(_GCR)
#define DMA_GSCR _DMA_GCRx(_GSCR)

/* **** */

enum {
	_CSDP = 0x00,
	_CCR0 = 0x02,
	_CICR = 0x04,
	_CSR = 0x06,
	_CSSA_L = 0x08,
	_CSSA_U = 0x0a,
	_CDSA_L = 0x0c,
	_CDSA_U = 0x0e,
	_CEN = 0x10,
	_CFN = 0x12,
	_CSFI = 0x14,
	_CSEI = 0x16,
	_CSAC = 0x18,
	_CDAC = 0x1a,
	_CDEI = 0x1c,
	_CDFI = 0x1e,
	_COLOR_L = 0x20,
	_COLOR_U = 0x22,
	_CCR2 = 0x24,
	_CLNK_CTRL = 0x28,
	_LCH_CTRL = 0x2a,
};

#define _DMA_CHrn(_r, _n) (SOC_OMAP_DMA_CH + REG_CHrn(_r, _n))
#define PPA2CHr(_ppa) ((_ppa) & 0x3f)
#define PPA2CHn(_ppa) (((_ppa) >> 6) & 0x0f)
#define PPA2p2CHn(_ppa) (&dma->ch[PPA2CHn(ppa)])
//#define PPA2p2CHr(_ppa, _r) (&PPA2p2CHn(ppa)->_r)
#define REG_CHrn(_r, _n) (_r + ((_n) * 0x40))

/* **** */

#define DMA_CCR(_x, _n) _DMA_CHrn(_CCR##_x, _n)
#define DMA_CDAC(_n) _DMA_CHrn(_CDAC, _n)
#define DMA_CDEI(_n) _DMA_CHrn(_CDEI, _n)
#define DMA_CDFI(_n) _DMA_CHrn(_CDFI, _n)
#define DMA_CDSA(_x, _n) _DMA_CHrn(_CDSA_##_x, _n)
#define DMA_CEN(_n) _DMA_CHrn(_CEN, _n)
#define DMA_CFN(_n) _DMA_CHrn(_CFN, _n)
#define DMA_CLNK_CTRL(_n) _DMA_CHrn(_CLNK_CTRL, _n)
#define DMA_CICR(_n) _DMA_CHrn(_CICR, _n)
#define DMA_COLOR(_x, _n) _DMA_CHrn(_COLOR_##_x, _n)
#define DMA_CSAC(_n) _DMA_CHrn(_CSAC, _n)
#define DMA_CSDP(_n) _DMA_CHrn(_CSDP, _n)
#define DMA_CSEI(_n) _DMA_CHrn(_CSEI, _n)
#define DMA_CSFI(_n) _DMA_CHrn(_CSFI, _n)
#define DMA_CSR(_n) _DMA_CHrn(_CSR, _n)
#define DMA_CSSA(_x, _n) _DMA_CHrn(_CSSA_##_x, _n)
#define DMA_LCH_CTRL(_n) _DMA_CHrn(_LCH_CTRL, _n)

/* **** */

enum {
	_DMA_LCD_CSDP = 0xc0,
	_DMA_LCD_CTRL = 0xc4,
	_DMA_LCD_TOP_B1_L = 0xc8,
	_DMA_LCD_TOP_B1_U = 0xca,
	
};

#define _DMA_LCD_(_x) _DMA_LCD_##_x
#define _DMA_LCDx(_x) (SOC_OMAP_DMA_LCD + _DMA_LCD_(_x))

#define DMA_LCD(_x) _DMA_LCDx(_x)

/* **** */

static int __soc_omap_dma_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	handle_free(param);

	return(0);
}

static int __soc_omap_dma_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	const soc_omap_dma_p dma = param;

	dma->gcr.gcr = (dma->gcr.gcr & ~mlBF(15, 5)) | _BV(3);
	dma->gcr.gscr &= ~_BV(3);

	for(unsigned n = 0; n < SOC_OMAP_DMA_CH_COUNT; n++) {
		soc_omap_dma_ch_p ch = &dma->ch[n];

		ch->ccr = 0;
		ch->cicr = (ch->cicr & ~mlBF(15, 6)) | 3;
		ch->clnk_ctrl &= ~mlBF(13, 5);
		ch->csdp = 0;
		ch->csr = 0;
		ch->lch_ctrl &= ~mlBF(14, 4);
	}

	const soc_omap_dma_lcd_p lcd = &dma->lcd;

	lcd->csdp = 0;
	lcd->ctrl = 0;

	return(0);
}

/* **** */

uint32_t _soc_omap_dma_ccr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->ccr, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Control Register\n\t");
		_LOG_("DST_AMODE: %01u", mlBFEXT(data, 15, 14));
		_LOG_(", SRC_AMODE: %01u", mlBFEXT(data, 13, 12));
		_LOG_(", END_PROG: %01u\n\t", BEXT(data, 11));
		_LOG_("OMAP_3_1_COMPATIBLE_DISABLE: %01u", BEXT(data, 10));
		_LOG_(", REPEAT: %01u", BEXT(data, 9));
		_LOG_(", AUTO_INIT: %01u", BEXT(data, 8));
		_LOG_(", ENABLE: %01u\n\t", BEXT(data, 7));
		_LOG_("PRIO: %01u", BEXT(data, 6));
		_LOG_(", FS: %01u", BEXT(data, 5));
		LOG_END(", SYNC: %02u", mlBFEXT(data, 4, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_ccr2(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->ccr2, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Control Register 2\n\t");
		_LOG_("RESERVED[15, 3]: 0x%04x", mlBFEXT(data, 15, 3));
		_LOG_(", BS: %01u", BEXT(data, 2));
		_LOG_(", TCE: %01u", BEXT(data, 1));
		LOG_END(", CFE: %01u", BEXT(data, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_cdac(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->cdac, write);

	if(write && _trace_mmio_dma) {
		LOG("DMA: Channel Destination Address Counter Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_cdei(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->cdei, write);

	if(write && _trace_mmio_dma) {
		LOG("DMA: Channel Destination Element Index Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_cdfi(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->cdfi, write);

	if(write && _trace_mmio_dma) {
		LOG("DMA: Channel Destination Frame Index Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_cdsa(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(BTST((sizeof(uint32_t) | sizeof(uint16_t)), size));

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32x_access(&ch->cdsa, ppa & 3, size, write);

	if(write && _trace_mmio_dma) {
		LOG("DMA: Channel Destination Start Address: 0x%08x", ch->cdsa);
	}

	return(data);
}

uint32_t _soc_omap_dma_cen(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->cen, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Element Number Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_cfn(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->cfn, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Frame Number Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_cicr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->cicr, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Interrupt Control Register\n\t");
		_LOG_("RESERVED[15:6]: 0x%02x", mlBFEXT(data, 15, 6));
		_LOG_(", BLOCK_IE: %01u", BEXT(data, 5));
		_LOG_(", LAST_IE: %01u", BEXT(data, 4));
		_LOG_(", FRAME_IE: %01u\n\t", BEXT(data, 3));
		_LOG_("HALF_IE: %01u", BEXT(data, 2));
		_LOG_(", DROP_IE: %01u", BEXT(data, 1));
		LOG_END(", TOUT_IE: %01u", BEXT(data, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_clnk_ctrl(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->clnk_ctrl, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Link Control Register\n\t");
		_LOG_("EL: %01u", BEXT(data, 15));
		_LOG_(", SL: %01u", BEXT(data, 14));
		_LOG_(", RESERVED[13, 3]: 0x%04x", mlBFEXT(data, 13, 3));
		_LOG_(", NID[4]: %01u", BEXT(data, 4));
		LOG_END(", NID[3:0]: %01u", mlBFEXT(data, 3, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_color(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(BTST((sizeof(uint32_t) | sizeof(uint16_t)), size));

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32x_access(&ch->color, ppa & 3, size, write);

	if(write && _trace_mmio_dma) {
		LOG("DMA: Color Parameter Register: 0x%08x", ch->color);
	}

	return(data);
}

uint32_t _soc_omap_dma_csac(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->csac, write);

	if(write && _trace_mmio_dma) {
		LOG("DMA: Source Channel Element Index Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_csdp(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->csdp, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Source Destination Parameters Register\n\t");
		_LOG_("DST_BURST_EN: %01u", mlBFEXT(data, 15, 14));
		_LOG_(", DST_PACK: %01u", BEXT(data, 13));
		_LOG_(", DST: %02u\n\t", mlBFEXT(data, 12, 9));
		_LOG_("SRC_BURST_EN: %01u", mlBFEXT(data, 8, 7));
		_LOG_(", SRC_PACK: %01u", BEXT(data, 6));
		_LOG_(", SRC: %02u\n\t", mlBFEXT(data, 5, 2));
		LOG_END("DATA_TYPE: %01u", mlBFEXT(data, 1, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_csei(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->csei, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Source Element Index Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_csfi(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->csfi, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Source Frame Index Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_csr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->csr, 0);

	if(write && _trace_mmio_dma) {
		LOG("DMA: [RO] Channel Satus Register\n\t");
	}

	return(data);
}

uint32_t _soc_omap_dma_cssa(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(BTST((sizeof(uint32_t) | sizeof(uint16_t)), size));

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32x_access(&ch->cssa, ppa & 3, size, write);

	if(write && _trace_mmio_dma) {
		LOG("DMA: Channel Source Start Address: 0x%08x", ch->cssa);
	}

	return(data);
}

uint32_t _soc_omap_dma_gcr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;

	const uint32_t data = mem_32_access(&dma->gcr.gcr, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Global Control Register\n\t");
		_LOG_("RESERVED[15, 5]: 0x%04x", mlBFEXT(data, 15, 5));
		_LOG_(", ROUND_ROBIN_DISABLE: %01u", BEXT(data, 4));
		_LOG_(", CLK_AUTOGATING_ON: %01u\n\t", BEXT(data, 3));
		_LOG_("FREE: %01u", BEXT(data, 2));
		LOG_END(", RESERVED[1:0]: %01u", mlBFEXT(data, 1, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_dma_gscr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;

	const uint32_t data = mem_32_access(&dma->gcr.gscr, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Global Software Compatible Register\n\t");
		_LOG_("RESERVED[15, 4]: 0x%04x", mlBFEXT(data, 15, 4));
		_LOG_(", OMAP3_1_MAPPING_DISABLE: %01u", BEXT(data, 3));
		LOG_END(", RESERVED[2:0]: %01u", mlBFEXT(data, 2, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_dma_lcd_csdp(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_lcd_p lcd = &dma->lcd;

	const uint32_t data = mem_32_access(&lcd->csdp, write);

	if(_trace_mmio_dma_lcd)
		CSX_MMIO_TRACE_MEM_ACCESS(dma->csx, ppa, size, write, data);

	if(write && _trace_mmio_dma_lcd) {
		LOG_START("DMA: LCD Channel Source Destination Parameters Register\n\t");
		_LOG_("BURST_EN_B2: %01u", mlBFEXT(data, 15, 14));
		_LOG_(", PACK_EN_B2: %01u", BEXT(data, 13));
		_LOG_(", DATA_TYPE_B2: %01u", mlBFEXT(data, 12, 11));
		_LOG_(", RESERVED[10, 9]: 0x%04x\n\t", mlBFEXT(data, 10, 9));
		_LOG_("BURST_EN_B1: %01u", mlBFEXT(data, 8, 7));
		_LOG_(", PACK_EN_B1: %01u", BEXT(data, 6));
		_LOG_(", RESERVED[10, 9]: 0x%04x", mlBFEXT(data, 5, 2));
		LOG_END(", DATA_TYPE_B1: %01u", mlBFEXT(data, 1, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_lcd_ctrl(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_lcd_p lcd = &dma->lcd;

	const uint32_t data = mem_32_access(&lcd->ctrl, write);

	if(_trace_mmio_dma_lcd)
		CSX_MMIO_TRACE_MEM_ACCESS(dma->csx, ppa, size, write, data);

	if(write && _trace_mmio_dma_lcd) {
		LOG_START("DMA: LCD Control Register\n\t");
		_LOG_("RESERVED[15:9]: 0x%02x", mlBFEXT(data, 15, 9));
		_LOG_(", LDP: %01u", BEXT(data, 8));
		_LOG_(", LSP: %01u", mlBFEXT(data, 7, 6));
		_LOG_(", BUSS_ERROR_IT_COND: %01u", BEXT(data, 5));
		_LOG_(", BUSS_2_IT_COND: %01u\n\t", BEXT(data, 4));
		_LOG_("BUSS_1_IT_COND: %01u", BEXT(data, 3));
		_LOG_(", BUSS_ERROR_IT_IE: %01u", BEXT(data, 2));
		_LOG_(", BLOCK_IT_IE: %01u", BEXT(data, 1));
		LOG_END(", BLOCK_MODE: %01u", BEXT(data, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_lcd_top_b1(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	uint32_t* var = &dma->lcd.top_b[0];

	const uint32_t data = mem_32x_access(var, (ppa & 3), size, write);

	if(_trace_mmio_dma_lcd)
		CSX_MMIO_TRACE_MEM_ACCESS(dma->csx, ppa, size, write, data);

	if(write && _trace_mmio_dma_lcd) {
		LOG_START("DMA: LCD Control Register\n\t");
		_LOG_("RESERVED[15:9]: 0x%02x", mlBFEXT(data, 15, 9));
		_LOG_(", LDP: %01u", BEXT(data, 8));
		_LOG_(", LSP: %01u", mlBFEXT(data, 7, 6));
		_LOG_(", BUSS_ERROR_IT_COND: %01u", BEXT(data, 5));
		_LOG_(", BUSS_2_IT_COND: %01u\n\t", BEXT(data, 4));
		_LOG_("BUSS_1_IT_COND: %01u", BEXT(data, 3));
		_LOG_(", BUSS_ERROR_IT_IE: %01u", BEXT(data, 2));
		_LOG_(", BLOCK_IT_IE: %01u", BEXT(data, 1));
		LOG_END(", BLOCK_MODE: %01u", BEXT(data, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_lch_ctrl(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;
	soc_omap_dma_ch_p ch = PPA2p2CHn(ppa);

	const uint32_t data = mem_32_access(&ch->lch_ctrl, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Logical Channel Control Register\n\t");
		_LOG_("LID: %01u", BEXT(data, 15));
		_LOG_(", RESERVED[14, 4]: 0x%04x", mlBFEXT(data, 14, 4));
		LOG_END(", LT[4:0]: %01u", mlBFEXT(data, 4, 0));
	}

	return(data);
}


/* **** */

soc_omap_dma_p soc_omap_dma_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_dma_h h2dma)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2dma);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_omap_dma_p dma = handle_calloc((void**)h2dma, 1, sizeof(soc_omap_dma_t));
	ERR_NULL(dma);

	dma->csx = csx;
	dma->mmio = mmio;

	/* **** */

	csx_mmio_callback_atexit(mmio, &dma->atexit, __soc_omap_dma_atexit, h2dma);
	csx_mmio_callback_atreset(mmio, &dma->atreset, __soc_omap_dma_atreset, dma);

	/* **** */

	return(dma);
}

/* **** */

void soc_omap_dma_init(soc_omap_dma_p dma)
{
	ERR_NULL(dma);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_mmio_p mmio = dma->mmio;

/* global dma control */
	csx_mmio_register_access(mmio, DMA_GCR, _soc_omap_dma_gcr, dma);
	csx_mmio_register_access(mmio, DMA_GSCR, _soc_omap_dma_gscr, dma);

/* dma channel */
	for(unsigned n = 0; n < SOC_OMAP_DMA_CH_COUNT; n++) {
		csx_mmio_register_access(mmio, DMA_CDAC(n), _soc_omap_dma_cdac, dma);
		csx_mmio_register_access(mmio, DMA_CDEI(n), _soc_omap_dma_cdei, dma);
		csx_mmio_register_access(mmio, DMA_CDFI(n), _soc_omap_dma_cdfi, dma);
		csx_mmio_register_access(mmio, DMA_CCR(0, n), _soc_omap_dma_ccr, dma);
		csx_mmio_register_access(mmio, DMA_CCR(2, n), _soc_omap_dma_ccr, dma);
		csx_mmio_register_access(mmio, DMA_CDSA(L, n), _soc_omap_dma_cdsa, dma);
		csx_mmio_register_access(mmio, DMA_CDSA(U, n), _soc_omap_dma_cdsa, dma);
		csx_mmio_register_access(mmio, DMA_CEN(n), _soc_omap_dma_cen, dma);
		csx_mmio_register_access(mmio, DMA_CFN(n), _soc_omap_dma_cfn, dma);
		csx_mmio_register_access(mmio, DMA_CICR(n), _soc_omap_dma_cicr, dma);
		csx_mmio_register_access(mmio, DMA_CLNK_CTRL(n), _soc_omap_dma_clnk_ctrl, dma);
		csx_mmio_register_access(mmio, DMA_COLOR(L, n), _soc_omap_dma_color, dma);
		csx_mmio_register_access(mmio, DMA_COLOR(U, n), _soc_omap_dma_color, dma);
		csx_mmio_register_access(mmio, DMA_CSDP(n), _soc_omap_dma_csdp, dma);
		csx_mmio_register_access(mmio, DMA_CSEI(n), _soc_omap_dma_csei, dma);
		csx_mmio_register_access(mmio, DMA_CSFI(n), _soc_omap_dma_csfi, dma);
		csx_mmio_register_access(mmio, DMA_CSAC(n), _soc_omap_dma_csac, dma);
		csx_mmio_register_access(mmio, DMA_CSR(n), _soc_omap_dma_csr, dma);
		csx_mmio_register_access(mmio, DMA_CSSA(L, n), _soc_omap_dma_cssa, dma);
		csx_mmio_register_access(mmio, DMA_CSSA(U, n), _soc_omap_dma_cssa, dma);
		csx_mmio_register_access(mmio, DMA_LCH_CTRL(n), _soc_omap_dma_lch_ctrl, dma);
	}

/* dma lcd */
	csx_mmio_register_access(mmio, DMA_LCD(CSDP), _soc_omap_dma_lcd_csdp, dma);
	csx_mmio_register_access(mmio, DMA_LCD(CTRL), _soc_omap_dma_lcd_ctrl, dma);
}
