#include "config.h"
#include "soc_omap_dma.h"

/* **** */

#include "csx_data.h"
#include "csx_mmio.h"

/* **** */

#include "bitfield.h"
#include "callback_qlist.h"
#include "handle.h"
#include "mem_access_le.h"

/* **** */

typedef struct soc_omap_dma_t {
	csx_p csx;
	csx_mmio_p mmio;

	uint8_t ch[0xdd00 - 0xd800];

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}soc_omap_dma_t;

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

#define _DMA_cn(_c, _n) (_c + ((_n) * 0x40))
#define _SOC_OMAP_DMA_cn(_c, _n) (SOC_OMAP_DMA + _DMA_cn(_c, _n))

#define _DMA_CCR(_x, _n) _DMA_cn(_CCR##_x, _n)
#define _DMA_CDAC(_n) _DMA_cn(_CDAC, _n)
#define _DMA_CDEI(_n) _DMA_cn(_CDEI, _n)
#define _DMA_CDFI(_n) _DMA_cn(_CDFI, _n)
#define _DMA_CDSA(_n) _DMA_cn(_CDSA_L, _n)
#define _DMA_CDSA_PPA2CH(_ppa) _DMA_CDSA((((_ppa) - _DMA_CDSA(0)) / 0x40))
#define _DMA_CEN(_n) _DMA_cn(_CEN, _n)
#define _DMA_CFN(_n) _DMA_cn(_CFN, _n)
#define _DMA_CICR(_n) _DMA_cn(_CICR, _n)
#define _DMA_CLNK_CTRL(_n) _DMA_cn(_CLNK_CTRL, _n)
#define _DMA_COLOR(_n) _DMA_cn(_COLOR_L, _n)
#define _DMA_COLOR_PPA2CH(_ppa) _DMA_COLOR((((_ppa) - _DMA_COLOR(0)) / 0x40))
#define _DMA_CSAC(_n) _DMA_cn(_CSAC, _n)
#define _DMA_CSDP(_n) _DMA_cn(_CSDP, _n)
#define _DMA_CSEI(_n) _DMA_cn(_CSEI, _n)
#define _DMA_CSFI(_n) _DMA_cn(_CSFI, _n)
#define _DMA_CSR(_n) _DMA_cn(_CSR, _n)
#define _DMA_CSSA(_n) _DMA_cn(_CSSA_L, _n)
#define _DMA_CSSA_PPA2CH(_ppa) _DMA_CSSA((((_ppa) - _DMA_CSSA(0)) / 0x40))
#define _DMA_LCH_CTRL(_n) _DMA_cn(_LCH_CTRL, _n)

static inline unsigned dma_ch_mem_access(soc_omap_dma_p dma, unsigned pat, size_t size, unsigned* write) {
	return(mem_access_le(&dma->ch[pat & 0xff], size, write));
}

static inline unsigned dma_ch_mem_read(soc_omap_dma_p dma, unsigned pat, size_t size, unsigned* write) {
	return(write ? *write : dma_ch_mem_access(dma, pat, size, 0));
}

static inline unsigned dma_ch16_mem_access(soc_omap_dma_p dma, unsigned pat, unsigned* write) {
	return(dma_ch_mem_access(dma, pat, sizeof(uint16_t), write));
}

static inline void dma_ch16_mask_and_set(soc_omap_dma_p dma, unsigned pat, uint32_t mask, uint32_t set) {
	unsigned data = dma_ch16_mem_access(dma, pat, 0) & mask;
	data |= (set & ~mask);

	dma_ch16_mem_access(dma, pat, &data);
}

static inline void dma_ch16_write(soc_omap_dma_p dma, unsigned pat, uint32_t data) {
	dma_ch16_mem_access(dma, pat, &data);
}

static inline unsigned dma_ch32_mem_access(soc_omap_dma_p dma, unsigned pat, unsigned* write) {
	return(dma_ch_mem_access(dma, pat, sizeof(uint32_t), write));
}

#define DMA_CCR(_x, _n) _SOC_OMAP_DMA_cn(_CCR##_x, _n)
#define DMA_CDAC(_n) _SOC_OMAP_DMA_cn(_CDAC, _n)
#define DMA_CDEI(_n) _SOC_OMAP_DMA_cn(_CDEI, _n)
#define DMA_CDFI(_n) _SOC_OMAP_DMA_cn(_CDFI, _n)
#define DMA_CDSA(_x, _n) _SOC_OMAP_DMA_cn(_CDSA_##_x, _n)
#define DMA_CEN(_n) _SOC_OMAP_DMA_cn(_CEN, _n)
#define DMA_CFN(_n) _SOC_OMAP_DMA_cn(_CFN, _n)
#define DMA_CLNK_CTRL(_n) _SOC_OMAP_DMA_cn(_CLNK_CTRL, _n)
#define DMA_CICR(_n) _SOC_OMAP_DMA_cn(_CICR, _n)
#define DMA_COLOR(_x, _n) _SOC_OMAP_DMA_cn(_COLOR_##_x, _n)
#define DMA_CSAC(_n) _SOC_OMAP_DMA_cn(_CSAC, _n)
#define DMA_CSDP(_n) _SOC_OMAP_DMA_cn(_CSDP, _n)
#define DMA_CSEI(_n) _SOC_OMAP_DMA_cn(_CSEI, _n)
#define DMA_CSFI(_n) _SOC_OMAP_DMA_cn(_CSFI, _n)
#define DMA_CSR(_n) _SOC_OMAP_DMA_cn(_CSR, _n)
#define DMA_CSSA(_x, _n) _SOC_OMAP_DMA_cn(_CSSA_##_x, _n)
#define DMA_LCH_CTRL(_n) _SOC_OMAP_DMA_cn(_LCH_CTRL, _n)

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

	for(unsigned n = 0; n < 1; n++) {
		dma_ch16_write(dma, _DMA_CCR(0, n), 0);
		dma_ch16_mask_and_set(dma, _DMA_CICR(n), mlBF(15, 6), 3);
		dma_ch16_mask_and_set(dma, _DMA_CLNK_CTRL(n), mlBF(13, 5), 0);
		dma_ch16_write(dma, _DMA_CSDP(n), 0);
		dma_ch16_write(dma, _DMA_CSR(n), 0);
		dma_ch16_mask_and_set(dma, _DMA_LCH_CTRL(n), mlBF(14, 4), 0);
	}

	return(0);
}

/* **** */

uint32_t _soc_omap_dma_ccr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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
		LOG_END("SYNC: %02u", mlBFEXT(data, 4, 0));
	}

	return(data);
}

uint32_t _soc_omap_dma_ccr2(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Destination Element Index Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_cdfi(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Channel Destination Frame Index Register: 0x%08x", data);
	}

	return(data);
}

uint32_t _soc_omap_dma_cdsa(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(BTST((sizeof(uint32_t) | sizeof(uint16_t)), size));

	const soc_omap_dma_p dma = param;

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

	if(write && _trace_mmio_dma) {
		const uint32_t cdsa = dma_ch32_mem_access(dma, _DMA_CDSA_PPA2CH(ppa), 0);
		LOG("DMA: Channel Destination Start Address: 0x%08x", cdsa);
	}

	return(data);
}

uint32_t _soc_omap_dma_cen(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

	if(write && _trace_mmio_dma) {
		const uint32_t cpr = dma_ch32_mem_access(dma, _DMA_COLOR_PPA2CH(ppa), 0);
		LOG("DMA: Color Parameter Register: 0x%08x", cpr);
	}

	return(data);
}

uint32_t _soc_omap_dma_csac(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_read(dma, ppa, size, write);

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

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

	if(write && _trace_mmio_dma) {
		const uint32_t cssa = dma_ch32_mem_access(dma, _DMA_CSSA_PPA2CH(ppa), 0);
		LOG("DMA: Channel Source Start Address: 0x%08x", cssa);
	}

	return(data);
}

uint32_t _soc_omap_dma_lch_ctrl(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint16_t) == size);

	const soc_omap_dma_p dma = param;

	const uint32_t data = dma_ch_mem_access(dma, ppa, size, write);

	if(write && _trace_mmio_dma) {
		LOG_START("DMA: Logican Channel Control Register\n\t");
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

	for(unsigned n = 0; n < 16; n++) {
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
}
