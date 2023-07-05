#include "config.h"
#include "soc_omap_lcd.h"

/* **** */

#include "csx_mmio.h"
#include "csx.h"

/* **** */

#include "callback_qlist.h"
#include "err_test.h"
#include "handle.h"
#include "mem_access_le.h"

/* **** */

typedef struct soc_omap_lcd_t {
	struct {
		unsigned ctrl;
		unsigned display_status;
		unsigned lineint;
		unsigned timing[3];
		unsigned status;
		unsigned subpanel;
	}r;

	csx_p csx;
	csx_mmio_p mmio;

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}soc_omap_lcd_t;

/* **** */

enum {
	_CTRL = 0x00,
	_TIMING0 = 0x04,
	_TIMING1 = 0x08,
	_TIMING2 = 0x0c,
	_STATUS = 0x10,
	_SUBPANEL = 0x14,
	_LINEINT = 0x18,
	_DISPLAY_STATUS = 0x1c,
};

#define LCDr(_r) (SOC_OMAP_LCD + (_r))

/* **** */

static int __soc_omap_lcd_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

	handle_free(param);
	return(0);
}

UNUSED_FN int __soc_omap_lcd_atreset(void* param)
{
	if(_trace_atreset) {
		LOG();
	}

	soc_omap_lcd_p lcd = param;

	lcd->r.ctrl = 0;
	lcd->r.lineint = 0;
	lcd->r.display_status = 0x3ff;
	lcd->r.timing[0] = 0xf;
	lcd->r.timing[1] = 0;
	lcd->r.timing[2] = 0;
	lcd->r.status = 0;
	lcd->r.subpanel = 0;

	return(0);
	UNUSED(param);
}

/* **** */

uint32_t _soc_omap_lcd_ctrl(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_lcd_p lcd = param;
//	const csx_p csx = lcd->csx;

	const uint32_t data = mem_access_le(&lcd->r.ctrl, size, write);

	if(_trace_mmio_lcd && write) {
		LOG_START("LCD: Control Register << 0x%08x\n\t", data);
		_LOG_("RESERVED[31:25]: 0x%02x", mlBFEXT(data, 31, 25));
		_LOG_(", STN_565: %01u", BEXT(data, 24));
		_LOG_(", TFT_Map: %01u", BEXT(data, 23));
		_LOG_(", LCDCB1: %01u", BEXT(data, 22));
		_LOG_(", PLM: %01u\n\t", mlBFEXT(data, 21, 20));
		_LOG_("FDD: 0x%02x", mlBFEXT(data, 19, 12));
		_LOG_(", PXL_GATED: %01u", BEXT(data, 11));
		_LOG_(", LINE_INT_CLR_SEL: %01u", BEXT(data, 10));
		_LOG_(", M8B: %01u", BEXT(data, 9));
		_LOG_(", LCDCB0: %01u\n\t", BEXT(data, 8));
		_LOG_("LCD_TFT: %01u", BEXT(data, 7));
		_LOG_(", LINE_INT_MASK: %01u", BEXT(data, 6));
		_LOG_(", LINE_INT_NIRQ_MASK: %01u", BEXT(data, 5));
		_LOG_(", LOAD_MASK: %01u\n\t", BEXT(data, 4));
		_LOG_("DONE_MASK: %01u", BEXT(data, 3));
		_LOG_(", VSYNC_MASK: %01u", BEXT(data, 2));
		_LOG_(", LCD_BW: %01u", BEXT(data, 1));
		LOG_END(", LCD_EN: %01u", BEXT(data, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_lcd_display_status(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_lcd_p lcd = param;
//	const csx_p csx = lcd->csx;

	const uint32_t data = mem_access_le(&lcd->r.display_status, size, 0);

	if(_trace_mmio_lcd && write) {
		LOG_START("LCD: [RO] Display Status Register << 0x%08x\n\t", data);
		_LOG_("RESERVED[31:10]: 0x%04x", mlBFEXT(data, 31, 10));
		LOG_END(", LINE_NUMBER: %04u", mlBFEXT(data, 9, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_lcd_lineint(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_lcd_p lcd = param;
//	const csx_p csx = lcd->csx;

	const uint32_t data = mem_access_le(&lcd->r.lineint, size, write);

	if(_trace_mmio_lcd && write) {
		LOG_START("LCD: Line Interrupt Register << 0x%08x\n\t", data);
		_LOG_("RESERVED[31:10]: 0x%04x", mlBFEXT(data, 31, 10));
		LOG_END(", LINE_INT_NUMBER: %04u", mlBFEXT(data, 9, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_lcd_timing0(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_lcd_p lcd = param;
//	const csx_p csx = lcd->csx;

	const uint32_t data = mem_access_le(&lcd->r.timing[0], size, write);

	if(_trace_mmio_lcd && write) {
		LOG_START("LCD: Timing 0 Register << 0x%08x\n\t", data);
		_LOG_("HBP: 0x%02x", mlBFEXT(data, 31, 24));
		_LOG_(", HFP: 0x%02x", mlBFEXT(data, 23, 16));
		_LOG_(", HSW: 0x%02x", mlBFEXT(data, 15, 10));
		LOG_END(", PPL: %4u", mlBFEXT(data, 9, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_lcd_timing1(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_lcd_p lcd = param;
//	const csx_p csx = lcd->csx;

	const uint32_t data = mem_access_le(&lcd->r.timing[1], size, write);

	if(_trace_mmio_lcd && write) {
		LOG_START("LCD: Timing 1 Register << 0x%08x\n\t", data);
		_LOG_("VBP: 0x%02x", mlBFEXT(data, 31, 24));
		_LOG_(", VFP: 0x%02x", mlBFEXT(data, 23, 16));
		_LOG_(", VSW: 0x%02x", mlBFEXT(data, 15, 10));
		LOG_END(", LPP: %4u", mlBFEXT(data, 9, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_lcd_timing2(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_lcd_p lcd = param;
//	const csx_p csx = lcd->csx;

	const uint32_t data = mem_access_le(&lcd->r.timing[2], size, write);

	if(_trace_mmio_lcd && write) {
		LOG_START("LCD: Timing 2 Register << 0x%08x\n\t", data);
		_LOG_("RESERVED[31:26]: 0x%02x", mlBFEXT(data, 31, 26));
		_LOG_(", ON_OFF: %01u", BEXT(data, 25));
		_LOG_(", RF: %01u", BEXT(data, 24));
		_LOG_(", IEO: %01u", BEXT(data, 23));
		_LOG_(", IPC: %01u\n\t", BEXT(data, 22));
		_LOG_("IHS: %01u", BEXT(data, 21));
		_LOG_(", IVS: %01u", BEXT(data, 20));
		_LOG_(", ACBI: 0x%02x", mlBFEXT(data, 19, 16));
		_LOG_(", ACB: 0x%02x", mlBFEXT(data, 15, 8));
		LOG_END(", PCD: 0x%02x", mlBFEXT(data, 7, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_lcd_status(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_lcd_p lcd = param;
//	const csx_p csx = lcd->csx;

	const uint32_t data = mem_access_le(&lcd->r.status, size, write);

	if(_trace_mmio_lcd && write) {
		LOG_START("LCD: Status Register << 0x%08x\n\t", data);
		_LOG_("RESERVED[31:7]: 0x%02x", mlBFEXT(data, 31, 7));
		_LOG_(", LP: %01u", BEXT(data, 6));
		_LOG_(", FUF: %01u", BEXT(data, 5));
		_LOG_(", LINE_INT: %01u\n\t", BEXT(data, 4));
		_LOG_("ABC: %01u", BEXT(data, 3));
		_LOG_(", SYNC_LOST: %01u", BEXT(data, 2));
		_LOG_(", VS: %01u", BEXT(data, 1));
		LOG_END(", DONE: %01u", BEXT(data, 0));
	}

	return(data);
	UNUSED(ppa);
}

uint32_t _soc_omap_lcd_subpanel(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint32_t) == size);

	const soc_omap_lcd_p lcd = param;
//	const csx_p csx = lcd->csx;

	const uint32_t data = mem_access_le(&lcd->r.subpanel, size, write);

	if(_trace_mmio_lcd && write) {
		LOG_START("LCD: Subpanel Register << 0x%08x\n\t", data);
		_LOG_("SPEN: %01u", BEXT(data, 31));
		_LOG_(", RESERVED[30]: %01u", BEXT(data, 30));
		_LOG_(", HOLS: %01u", BEXT(data, 29));
		_LOG_(", RESERVED[28:26]: 0x%02x\n\t", mlBFEXT(data, 28, 26));
		_LOG_("LPPT: %04u", mlBFEXT(data, 25, 16));
		LOG_END(", DPD: 0x%04x", mlBFEXT(data, 15, 0));
	}

	return(data);
	UNUSED(ppa);
}

/* **** */

soc_omap_lcd_p soc_omap_lcd_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_lcd_h h2lcd)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2lcd);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_omap_lcd_p lcd = handle_calloc((void**)h2lcd, 1, sizeof(soc_omap_lcd_t));
	ERR_NULL(lcd);

	lcd->csx = csx;
	lcd->mmio = mmio;

	csx_mmio_callback_atexit(mmio, &lcd->atexit, __soc_omap_lcd_atexit, h2lcd);
	csx_mmio_callback_atreset(mmio, &lcd->atreset, __soc_omap_lcd_atreset, lcd);

	/* **** */

	return(lcd);
}


void soc_omap_lcd_init(soc_omap_lcd_p lcd)
{
	ERR_NULL(lcd);

	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_mmio_p mmio = lcd->mmio;

	csx_mmio_register_access(mmio, LCDr(_CTRL), _soc_omap_lcd_ctrl, lcd);
	csx_mmio_register_access(mmio, LCDr(_DISPLAY_STATUS), _soc_omap_lcd_display_status, lcd);
	csx_mmio_register_access(mmio, LCDr(_LINEINT), _soc_omap_lcd_lineint, lcd);
	csx_mmio_register_access(mmio, LCDr(_TIMING0), _soc_omap_lcd_timing0, lcd);
	csx_mmio_register_access(mmio, LCDr(_TIMING1), _soc_omap_lcd_timing1, lcd);
	csx_mmio_register_access(mmio, LCDr(_TIMING2), _soc_omap_lcd_timing2, lcd);
	csx_mmio_register_access(mmio, LCDr(_STATUS), _soc_omap_lcd_status, lcd);
	csx_mmio_register_access(mmio, LCDr(_SUBPANEL), _soc_omap_lcd_subpanel, lcd);
}
