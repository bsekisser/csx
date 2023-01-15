#include "soc_mmio_uart.h"

/* **** soc includes */

#include "soc_mmio_omap.h"
#include "soc_omap_5912.h"

/* **** csx includes */

#include "csx_data.h"
#include "csx_mmio.h"
#include "csx_mmio_reg.h"

/* **** local includes */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
#include <string.h>

/* **** */

#define MMIO_LIST \
	MMIO(0xfffb, 0x0808, 0x0000, 0x0000, 8, MEM_RW, UART2_EFR) \
	MMIO(0xfffb, 0x080c, 0x0000, 0x0000, 8, MEM_RW, UART2_LCR) \
	MMIO(0xfffb, 0x0810, 0x0000, 0x0000, 8, MEM_RW, UART2_MCR) \
	MMIO(0xfffb, 0x081c, 0x0000, 0x0000, 8, MEM_RW, UART2_SPR) \
	MMIO(0xfffb, 0x0840, 0x0000, 0x0000, 8, MEM_RW, UART2_SCR) \
	MMIO(0xfffb, 0x0854, 0x0000, 0x0000, 8, MEM_RW, UART2_SYSC) \
	MMIO(0xfffb, 0x0858, 0x0000, 0x0000, 8, MEM_RW, UART2_SYSS) \

#define TRACE_LIST
#include "soc_mmio_trace.h"
#undef TRACE_LIST

/* **** */

#include "csx_mmio_trace.h"

#define UART1_TRACE_LIST \
	MMIO_TRACE(0xfffb, 0x000c,  8, RW, 0x0000, 0x0000, UART1_LCR) \
	MMIO_TRACE(0xfffb, 0x0054,  8, RW, 0x0000, 0x0000, UART1_SYSC) \
	MMIO_TRACE(0xfffb, 0x0058,  8, RW, 0x0000, 0x0000, UART1_SYSS) \
	MMIO_TRACE_LIST_END

#define UART2_TRACE_LIST \
	MMIO_TRACE(0xfffb, 0x080c,  8, RW, 0x0000, 0x0000, UART2_LCR) \
	MMIO_TRACE(0xfffb, 0x0854,  8, RW, 0x0000, 0x0000, UART2_SYSC) \
	MMIO_TRACE(0xfffb, 0x0858,  8, RW, 0x0000, 0x0000, UART2_SYSS) \
	MMIO_TRACE_LIST_END

#define UART3_TRACE_LIST \
	MMIO_TRACE(0xfffb, 0x980c,  8, RW, 0x0000, 0x0000, UART3_LCR) \
	MMIO_TRACE(0xfffb, 0x9854,  8, RW, 0x0000, 0x0000, UART3_SYSC) \
	MMIO_TRACE(0xfffb, 0x9858,  8, RW, 0x0000, 0x0000, UART3_SYSS) \
	MMIO_TRACE_LIST_END

#define MMIO_TRACE MMIO_TRACE_T
csx_mmio_trace_t _soc_omap_uart_trace_list[3][0x18] = {
	{ UART1_TRACE_LIST },
	{ UART2_TRACE_LIST },
	{ UART3_TRACE_LIST },
};
#undef MMIO_TRACE

/* **** */


/* **** */

enum {
	/* offsets are 0xXX * S
	 * 
	 * where S ==
	 * 	1	--	8 bit aligned
	 *	2	--	16 bit aligned
	 *	4	--	32 bit aligned
	 * 
	 * not sure arm omap documentation makes sense --- WTF?
	 * 
	 * 	1		2		4
	 * 	0x01,	0x02,	0x04,
	 * 	0x02,	0x04,	0x08,
	 * 	0x03,	0x06,	0x0c,	LCR
	 * 	0x04,	0x08,	0x10,
	 *	0x05,	0x0a,	0x14,
	 * 	0x06,	0x0c,	0x18,
	 * 	0x07,	0x0e,	0x1c,
	 * 	0x08,	0x10,	0x20,
	 * 	0x09,	0x12,	0x24,
	 *	0x0a,	0x14,	0x28,
	 * 	0x0b,	0x16,	0x2c,
	 * 	0x0c,	0x18,	0x30,
	 * 	0x0d,	0x1a,	0x34,
	 *	0x0e,	0x1c,	0x38,
	 * 	0x0f,	0x1e,	0x3c,
	 * 	0x10,	0x20,	0x40,
	 *	0x11,	0x22,	0x44,
	 * 	0x12,	0x24,	0x48,
	 * 	0x13,	0x26,	0x4c,	XXXX -- 0x13 -- reserved
	 * 	0x14,	0x28,	0x50,
	 * 	0x15,	0x2a,	0x54,
	 * 	0x16,	0x2c,	0x58,	SYSC
	 *	0x17,	0x2e,	0x5c,	SYSS
	 */

	_UART_0x08 = 0x08,	/*	iir, fcr, efr */
	_UART_LCR = 0x0c,
	MCR = 0x10,
	SCR = 0x40,
	SPR = 0x1c,
	_UART_SYSC = 0x54,
	_UART_SYSS = 0x58,
//
	_UART_EFR = _UART_0x08,
	_UART_FCR,
	_UART_IIR,
};

enum {
	_UART_LCR_DIV_EN = 7,
};

enum {
	_UART_SYSC_SoftReset = 2,
};

enum {
	_UART_SYSS_ResetDone = 0,
};

CSX_MMIO_DATAREG_GET(UART_EFR, uint8_t);
CSX_MMIO_DATAREG_SET(UART_EFR, uint8_t);
CSX_MMIO_DATAREG_GET(UART_IIR, uint8_t);
CSX_MMIO_DATAREG_GET(UART_LCR, uint8_t);
CSX_MMIO_DATAREG_SET(UART_LCR, uint8_t);
CSX_MMIO_DATAREG_SET(UART_SYSC, uint8_t);
CSX_MMIO_DATAREG_RMW(UART_SYSS, uint8_t);

CSX_MMIO_DATAREGBIT_GET(UART_LCR, DIV_EN);

/* **** */

static uint32_t _uart_efr_r(void* param, void* data, uint32_t mpa, uint8_t size)
{
//	const soc_omap_uart_p uart = param;
//	const csx_p csx = uart->csx;

	uint32_t value = UART_EFR(data, 0);

	LOG("%02u:[0x%08x] >> 0x%08x: UART_EFR", size, mpa, value);
	
	return(value);

	UNUSED(param);
}


static void _uart_efr_w(void* param, void* data, uint32_t mpa, uint32_t value, uint8_t size)
{
//	const soc_omap_uart_p uart = param;
//	const csx_p csx = uart->csx;

	LOG("%02u:[0x%08x] >> 0x%08x: UART_EFR", size, mpa, value);

	LOG_START("UART Enhanced Feature Register\n\t");
	_LOG_("AUTO_CTS_EN: %01u", BEXT(value, 7));
	_LOG_(", AUTO_RTS_EN: %01u", BEXT(value, 6));
	_LOG_(", SPECIAL_CHAR_DETECT: %01u", BEXT(value, 5));
	_LOG_(", ENHANCED_FN: %01u", BEXT(value, 4));
	LOG_END(", SW_FLOW_CONTROL: %01u", mlBFEXT(value, 3, 0));
	
	UART_EFR_SET(data, value, 0);

	UNUSED(param);
}

static uint32_t _uart_fcr_r(void* param, void* data, uint32_t mpa, uint8_t size)
{ return(0); }

static void _uart_fcr_w(void* param, void* data, uint32_t mpa, uint32_t value, uint8_t size)
{}

static uint32_t _uart_iir_r(void* param, void* data, uint32_t mpa, uint8_t size)
{
//	const soc_omap_uart_p uart = param;
//	const csx_p csx = uart->csx;

	uint32_t value = UART_IIR(data, 0);

	LOG("%02u:[0x%08x] >> 0x%08x: UART_IIR", size, mpa, value);

	return(value);

	UNUSED(param);
}

static void _uart_lcr_w(void* param, void* data, uint32_t mpa, uint32_t value, uint8_t size)
{
//	const soc_omap_uart_p uart = param;
//	const csx_p csx = uart->csx;

	LOG("%02u:[0x%08x] << 0x%08x: UART_LCR", size, mpa, value);

	LOG_START("UART Line Control Register\n\t");
	_LOG_("DIV_EN: %01u", BEXT(value, 7));
	_LOG_(", BREAK_EN: %01u", BEXT(value, 6));
	_LOG_(", PARITY TYPE2: %01u", BEXT(value, 5));
	_LOG_(", PARITY TYPE1: %01u", BEXT(value, 4));
	_LOG_(", PARITY EN: %01u", BEXT(value, 3));
	_LOG_(", NB STOP: %01u", BEXT(value, 2));
	LOG_END(", CHAR_LENGTH: %01u", mlBFEXT(value, 1, 0));
	
	UART_LCR_SET(data, value, 0);

	UNUSED(param);
}

static void _uart_sysc_w(void* param, void* data, uint32_t mpa, uint32_t value, uint8_t size)
{
	const soc_omap_uart_p uart = param;
	const csx_p csx = uart->csx;

	LOG("%02u:[0x%08x] << 0x%08x: UART_SYSC", size, mpa, value);

	LOG_START("UART System Configuration Register\n\t");
	_LOG_("Reserved: %02u", mlBFEXT(value, 7, 5));
	_LOG_(", IdleMode: %02u", mlBFEXT(value, 4, 3));
	_LOG_(", EnaWakeUp: %01u", BEXT(value, 2));
	_LOG_(", SoftReset: %01u", BEXT(value, 1));
	LOG_END(", AutoIdle: %01u", BEXT(value, 0));

	if(BEXT(value, _UART_SYSC_SoftReset)) {
		csx_mmio_module_reset(csx, mpa);

		BCLR(value, _UART_SYSC_SoftReset);
		UART_SYSS_RMW(data, _UART_SYSS_ResetDone, _MMIO_OR);
	}

	UART_SYSC_SET(data, value, 0);
}

/* **** */

typedef struct _uart_regmap_t* _uart_regmap_p;
typedef struct _uart_regmap_t {
	struct {
		csx_mmio_read_fn rfn;
		csx_mmio_write_fn wfn;
	}lcr70;
	struct {
		csx_mmio_read_fn rfn;
		csx_mmio_write_fn wfn;
	}lcr71;
	struct {
		csx_mmio_read_fn rfn;
		csx_mmio_write_fn wfn;
	}xbf;
}_uart_regmap_t;

static _uart_regmap_t _uart_regmap_list[0x80] = {
//	[_UART_0x08] = { {_uart_iir_r, _uart_fcr_w}, {_uart_iir_r, _uart_fcr_w}, {_uart_efr_r, _uart_efr_w} },
	[_UART_0x08] = { _uart_iir_r, _uart_fcr_w, _uart_iir_r, _uart_fcr_w, _uart_efr_r, _uart_efr_w },
};

static uint32_t _uart_0x08_r(void* param, void* data, uint32_t mpa, uint8_t size)
{
	LOG("0x%08x, 0x%08x, 0x%08x", _UART_EFR, _UART_FCR, _UART_IIR);
	
	if(0 == UART_LCR_DIV_EN(data)) {
		return(_uart_iir_r(param, data, mpa, size));
	} else {
		if(0xbf != UART_LCR(data, 0))
			return(_uart_iir_r(param, data, mpa, size));
		else
			return(_uart_efr_r(param, data, mpa, size));
	}
}

static void _uart_0x08_w(void* param, void* data, uint32_t mpa, uint32_t value, uint8_t size)
{
	LOG("0x%08x, 0x%08x, 0x%08x", _UART_EFR, _UART_FCR, _UART_IIR);
	
	if(0 == UART_LCR_DIV_EN(data)) {
		return(_uart_fcr_w(param, data, mpa, value, size));
	} else {
		if(0xbf != UART_LCR(data, 0))
			return(_uart_fcr_w(param, data, mpa, value, size));
		else
			return(_uart_efr_w(param, data, mpa, value, size));
	}
}

/* **** */

static void soc_mmio_uart_write(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size);

static soc_mmio_peripheral_t uart_peripheral[3] = {
	{
		.base = CSX_MMIO_UART2_BASE,
		.trace_list = trace_list,

		.reset = 0,

		.read = 0,
		.write = soc_mmio_uart_write
	},
};

int soc_mmio_uart_init(csx_p csx, soc_mmio_p mmio, soc_mmio_uart_h h2uart)
{
	soc_mmio_uart_p uart = calloc(1, sizeof(soc_mmio_uart_t));

	ERR_NULL(uart);
	if(!uart)
		return(-1);

	uart->csx = csx;
	uart->mmio = mmio;

	*h2uart = uart;

	/* **** */

//	soc_mmio_peripheral(mmio, uart_peripheral, uart);

	/* **** */

	return(0);
}

static void soc_mmio_uart_write(void* param, void* data, uint32_t addr, uint32_t value, uint8_t size)
{
	const soc_mmio_uart_p uart = param;
	const csx_p csx = uart->csx;

	const ea_trace_p eat = soc_mmio_trace(csx->mmio, 0, addr);
	if(eat)
	{
		switch(addr & 0xff)
		{
			case MCR:
				LOG_START("UART Modem Control Register\n\t");
				_LOG_("RESERVED: %01u", BEXT(value, 7));
				_LOG_(", TCR_TLR: %01u", BEXT(value, 6));
				_LOG_(", XON_EN: %01u", BEXT(value, 5));
				_LOG_(", LOOPBACK_EN: %01u", BEXT(value, 4));
				_LOG_(", CD_STS_CH: %01u", BEXT(value, 3));
				_LOG_(", RI_STS_CH: %01u", BEXT(value, 2));
				_LOG_(", RTS: %01u", BEXT(value, 1));
				LOG_END(", DTR: %01u", BEXT(value, 0));
				break;
			case SCR:
				LOG("UART Supplementary Control Register\n\t");
				_LOG_("RX_TRIG_GRANU1: %01u", BEXT(value, 7));
				_LOG_(", TX_TRIG_GRANU1: %01u", BEXT(value, 6));
				_LOG_(", DSR_IT: %01u", BEXT(value, 5));
				_LOG_(", RX_CTS_DSR_WAKE_UP_ENABLE: %01u", BEXT(value, 4));
				_LOG_(", TX_EMPTY_CTL_IT: %01u", BEXT(value, 3));
				_LOG_(", DMA_MODE_2: %01u", mlBFEXT(value, 2, 1));
				LOG_END(", DMA_MODE_CTL: %01u", BEXT(value, 0));
				break;
			case SPR:
				LOG("UART Scratchpad Register: 0x%03x", value);
				break;
		}

		csx_data_write(data + (addr & 0xff), value, size);
	} else {
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

/* **** */

static uint32_t SOC_UARTi_BASE[3] = {
	SOC_UART1_BASE, SOC_UART2_BASE, SOC_UART3_BASE
};

int soc_omap_uart_init(csx_p csx, soc_omap_uart_h h2uart, int i)
{
	assert((_UART_EFR != _UART_FCR) && (_UART_FCR != _UART_IIR) && (_UART_EFR != _UART_IIR));
	
#define UARTx_(_x, _o) ((SOC_UARTi_BASE[_x - 1]) + (_UART_ ## _o))
//#define UARTx_o_s_(_x, _o, _s) ((SOC_UARTi_BASE[_x - 1]) + ((_o) * sizeof(_s)))

	soc_omap_uart_p uart = calloc(1, sizeof(soc_omap_uart_t));

	ERR_NULL(uart);
	if(!uart)
		return(-1);

	uart->csx = csx;

	*h2uart = uart;

	/* **** */

	csx_mmio_register_read(csx, _uart_0x08_r, UARTx_(i, 0x08), uart);
	csx_mmio_register_write(csx, _uart_0x08_w, UARTx_(i, 0x08), uart);

	csx_mmio_register_write(csx, _uart_lcr_w, UARTx_(i, LCR), uart);
	csx_mmio_register_write(csx, _uart_sysc_w, UARTx_(i, SYSC), uart);
	
//	csx_mmio_register_module_read(csx, SOC_UARTi_BASE[i], soc_mmio_uart_read);
//	csx_mmio_register_module_write(csx, SOC_UARTi_BASE[i], soc_mmio_uart_write);

	csx_mmio_register_trace_list(csx, _soc_omap_uart_trace_list[i - 1]);

	/* **** */

	return(0);
}
