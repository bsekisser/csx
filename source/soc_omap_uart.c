#include "soc_omap_uart.h"

#include "csx_data.h"
#include "csx_mmio.h"
#include "csx_soc_omap.h"
#include "csx.h"

/* **** */

#include "libbse/include/bitfield.h"
#include "libbse/include/callback_qlist.h"
#include "libbse/include/err_test.h"
#include "libbse/include/handle.h"
#include "libbse/include/log.h"

/* **** */

#include <assert.h>
#include <errno.h>
#include <string.h>

/* **** */

#undef DEBUG
//#define DEBUG(_x) _x
#define DEBUG(_X)

/* **** */

typedef struct soc_omap_uart_unit_t* soc_omap_uart_unit_p;
typedef struct soc_omap_uart_unit_t {
	uint8_t efr;
	uint8_t fcr;
	uint8_t lcr;
	uint8_t mcr;
	uint8_t scr;
	uint8_t spr;
	uint8_t sysc;
	uint8_t syss;
	uint8_t tlr;
}soc_omap_uart_unit_t;

typedef struct soc_omap_uart_t {
	csx_p csx;
	csx_mmio_p mmio;
	
	soc_omap_uart_unit_t unit[3];

	callback_qlist_elem_t atexit;
	callback_qlist_elem_t atreset;
}soc_omap_uart_t;

/* **** */

enum {
	_x08 = 0x08,
	_LCR = 0x0c,
	_x10 = 0x10,
	_x1c = 0x1c,
	_SCR = 0x40,
	_SYSC = 0x54,
	_SYSS = 0x58,
//
// 0x08 -- efr, fcr, iir
//
	_EFR = _x08,
	_FCR = _x08,
//	_IIR = _x08,
//
// 0x10 -- mcr, xon1
//
	_MCR = _x10,
//	_XON1 = _x10,
//
// 0x1c -- spr, tlr, xoff2
//
	_SPR = _x1c,
	_TLR = _x1c,
//	_XOFF2 = _x1c,
};

enum {
	SYSC_SoftReset = 2,
};

enum {
	SYSS_ResetDone = 0,
};

/* **** */

static int __soc_omap_uart_atexit(void* param)
{
	if(_trace_atexit) {
		LOG();
	}

//	soc_omap_uart_h h2uart = param;
//	soc_omap_uart_p uart = *h2uart;

	handle_free(param);

	return(0);
}

static int __soc_omap_uart_unit_reset(soc_omap_uart_unit_p uu) {
	memset(uu, 0, sizeof(soc_omap_uart_unit_t));
	
	BSET(uu->syss, SYSS_ResetDone);
	
	return(0);
}

static int __soc_omap_uart_atreset(void* param) {
	if(_trace_atreset)
		LOG();

	soc_omap_uart_p uart = param;

	for(unsigned uux = 0; uux < 3; uux++)
		__soc_omap_uart_unit_reset(&uart->unit[uux]);
	
	return(0);
}

static soc_omap_uart_unit_p __uart_unit(soc_omap_uart_p uart, uint32_t ppa) {
	uint8_t uux = 0;

	switch(ppa & ~0xffU) {
		case SOC_OMAP_UART3:
			uux++;
			__attribute__((fallthrough));
		case SOC_OMAP_UART2:
			uux++;
			__attribute__((fallthrough));
		case SOC_OMAP_UART1:
			break;
		default:
			LOG_ACTION(exit(-1));
			break;
	}

	return(&uart->unit[uux]);
}

/* **** */

static uint32_t _soc_omap_uart_lcr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint8_t) == size);

	const soc_omap_uart_p uart = param;
//	const csx_p csx = uart->csx;

	uint32_t data = csx_data_mem_access(&__uart_unit(uart, ppa)->lcr, size, write);

	if(write && _trace_mmio_uart) {
		LOG_START("UART Line Control Register\n\t");
		_LOG_("DIV_EN: %01u", BEXT(data, 7));
		_LOG_(", BREAK_EN: %01u", BEXT(data, 6));
		_LOG_(", PARITY TYPE2: %01u", BEXT(data, 5));
		_LOG_(", PARITY TYPE1: %01u", BEXT(data, 4));
		_LOG_(", PARITY EN: %01u", BEXT(data, 3));
		_LOG_(", NB STOP: %01u", BEXT(data, 2));
		LOG_END(", CHAR_LENGTH: %01u", mlBFEXT(data, 1, 0));
	}

	return(data);
}

static uint32_t _soc_omap_uart_scr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint8_t) == size);

	const soc_omap_uart_p uart = param;

	uint32_t data = csx_data_mem_access(&__uart_unit(uart, ppa)->scr, size, write);

	if(write && _trace_mmio_uart) {
		LOG_START("UART Supplementary Control Register\n\t");
		_LOG_("RX_TRIG_GRANU1: %01u", BEXT(data, 7));
		_LOG_(", TX_TRIG_GRANU1: %01u", BEXT(data, 6));
		_LOG_(", DSR_IT: %01u", BEXT(data, 5));
		_LOG_(", RX_CTS_DSR_WAKE_UP_ENABLE: %01u", BEXT(data, 4));
		_LOG_(", TX_EMPTY_CTL_IT: %01u", BEXT(data, 3));
		_LOG_(", DMA_MODE_2: %01u", mlBFEXT(data, 2, 1));
		LOG_END(", DMA_MODE_CTL: %01u", BEXT(data, 0));
	}

	return(data);
}

static uint32_t _soc_omap_uart_sysc(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint8_t) == size);
	
	const soc_omap_uart_p uart = param;
	const soc_omap_uart_unit_p uart_unit = __uart_unit(uart, ppa);

	uint32_t data = write ? *write : uart_unit->sysc;

	if(write) {
		if(_trace_mmio_uart) {
			LOG_START("UART System Configuration Register\n\t");
			_LOG_("Reserved: %02u", mlBFEXT(data, 7, 5));
			_LOG_(", IdleMode: %02u", mlBFEXT(data, 4, 3));
			_LOG_(", EnaWakeUp: %01u", BEXT(data, 2));
			_LOG_(", SoftReset: %01u", BEXT(data, 1));
			LOG_END(", AutoIdle: %01u", BEXT(data, 0));
		}

		if(BTST(data, SYSC_SoftReset)) {
			__soc_omap_uart_unit_reset(uart_unit);
			BCLR(data, SYSC_SoftReset);
		}

		uart_unit->sysc = data;
	}

	return(data);
}

static uint32_t _soc_omap_uart_syss(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint8_t) == size);
	
	const soc_omap_uart_p uart = param;
	const soc_omap_uart_unit_p uart_unit = __uart_unit(uart, ppa);

	// read only register

	return(uart_unit->syss);
	
	UNUSED(write);
}

/* **** */

static uint32_t _soc_omap_uart_x08_efr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{ // 0x08
	const soc_omap_uart_p uart = param;
	const soc_omap_uart_unit_p uart_unit = __uart_unit(uart, ppa);
	
	if(_check_pedantic_mmio) {
		if(_check_pedantic_mmio_size)
			assert(sizeof(uint8_t) == size);
		assert(0xbf == uart_unit->lcr);
	}

	uint32_t data = csx_data_mem_access(&uart_unit->efr, size, write);

	if(write && _trace_mmio_uart) {
		LOG_START("UART Enhanced Feature Register\n\t");
		_LOG_("AUTO_CTS_EN: %01u", BEXT(data, 7));
		_LOG_(", AUTO_RTS_EN: %01u", BEXT(data, 6));
		_LOG_(", SPECIAL_CHAR_DETECT: %01u", BEXT(data, 5));
		_LOG_(", ENHANCED_FN: %01u", BEXT(data, 4));
		LOG_END(", SW_FLOW_CONTROL: %01u", mlBFEXT(data, 3, 0));
	}

	return(data);
}

static uint32_t _soc_omap_uart_x08_fcr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{ // 0x08
	const soc_omap_uart_p uart = param;
	const soc_omap_uart_unit_p uart_unit = __uart_unit(uart, ppa);
	
	if(_check_pedantic_mmio) {
		if(_check_pedantic_mmio_size)
			assert(sizeof(uint8_t) == size);
		assert(0xbf != uart_unit->lcr);
		assert(0 != write);
	}

	// write only register

	const uint32_t data = write ? *write : 0;

	if(write) {
		if(_trace_mmio_uart) {
			LOG_START("UART FIFO Control Register\n\t");
			_LOG_("RX_FIFO_TRIG: %01u", mlBFEXT(data, 7, 6));
			_LOG_(", TX_FIFO_TRIG: %01u", mlBFEXT(data, 5, 4));
			_LOG_(", DMA_MODE: %01u", BEXT(data, 3));
			_LOG_(", TX_FIFO_CLEAR: %01u", BEXT(data, 2));
			_LOG_(", RX_FIFO_CLEAR: %01u", BEXT(data, 1));
			LOG_END(", FIFO_EN: %01u", BEXT(data, 0));
		}

		uart_unit->fcr = data & ~(4 + 2);
	}

	return(0);
}

static uint32_t _soc_omap_uart_x08(void* param, uint32_t ppa, size_t size, uint32_t* write)
{ // efr, fcr, iir
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint8_t) == size);

	soc_omap_uart_unit_p uart_unit = __uart_unit(param, ppa);
	
	DEBUG(LOG("lcr = 0x%02x, efr[4] = %1u, mcr[6] = %1u",
		uart_unit->lcr, BEXT(uart_unit->efr, 4), BEXT(uart_unit->mcr, 6)));

	if(0xbf == uart_unit->lcr)
		return(_soc_omap_uart_x08_efr(param, ppa, size, write));
	else {
		if(write) {
			return(_soc_omap_uart_x08_fcr(param, ppa, size, write));
		} else {
			LOG_ACTION(exit(-1));
;//			return(_soc_omap_uart_iir(param, ppa, size, write));
		}
	}

	return(0);
}

/* **** */

static uint32_t _soc_omap_uart_x10_mcr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_uart_p uart = param;
	const soc_omap_uart_unit_p uart_unit = __uart_unit(uart, ppa);
	
	if(_check_pedantic_mmio) {
		if(_check_pedantic_mmio_size)
			assert(sizeof(uint8_t) == size);
		assert(0xbf != uart_unit->lcr);
	}

	uint32_t data = write ? *write : uart_unit->mcr;

	if(write) {
		const uint8_t mask = BTST(uart_unit->efr, 4) ? 0xff : mlBF(4, 0);
		
		if(_trace_mmio_uart) {
			LOG_START("UART Modem Control Register\n\t");
			_LOG_("RESERVED: %01u", BEXT(data, 7));
			_LOG_(", TCR_TLR: %01u", BEXT(data, 6));
			_LOG_(", XON_EN: %01u", BEXT(data, 5));
			_LOG_(", LOOPBACK_EN: %01u", BEXT(data, 4));
			_LOG_(", CD_STS_CH: %01u", BEXT(data, 3));
			_LOG_(", RI_STS_CH: %01u", BEXT(data, 2));
			_LOG_(", RTS: %01u", BEXT(data, 1));
			LOG_END(", DTR: %01u", BEXT(data, 0));
		}

		uart_unit->mcr = (uart_unit->mcr & ~mask) | (data & mask);
	}

	return(data);
}

static uint32_t _soc_omap_uart_x10(void* param, uint32_t ppa, size_t size, uint32_t* write)
{ // mcr, xon1
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint8_t) == size);

	soc_omap_uart_unit_p uart_unit = __uart_unit(param, ppa);
	
	DEBUG(LOG("lcr = 0x%02x, efr[4] = %1u, mcr[6] = %1u",
		uart_unit->lcr, BEXT(uart_unit->efr, 4), BEXT(uart_unit->mcr, 6)));

	if(0xbf == uart_unit->lcr) {
		LOG_ACTION(exit(-1));
//		return(_soc_omap_uart_xon_addr1(param, ppa, size, write));
	} else {
		return(_soc_omap_uart_x10_mcr(param, ppa, size, write));
	}

	return(0);
}

/* **** */

static uint32_t _soc_omap_uart_x1c_spr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_uart_p uart = param;
	const soc_omap_uart_unit_p uart_unit = __uart_unit(uart, ppa);

	if(_check_pedantic_mmio) {
		if(_check_pedantic_mmio_size)
			assert(sizeof(uint8_t) == size);
		assert(0xbf != uart_unit->lcr);
		assert(0 == (BTST(uart_unit->efr, 4) && BTST(uart_unit->mcr, 6)));
	}

	uint32_t data = csx_data_mem_access(&__uart_unit(uart, ppa)->spr, size, write);

	if(write && _trace_mmio_uart) {
		LOG("UART Scratchpad Register: 0x%03x", data);
	}

	return(data);
}

static uint32_t _soc_omap_uart_x1c_tlr(void* param, uint32_t ppa, size_t size, uint32_t* write)
{ // 0x1c
	const soc_omap_uart_p uart = param;
	const soc_omap_uart_unit_p uart_unit = __uart_unit(uart, ppa);

	if(_check_pedantic_mmio) {
		if(_check_pedantic_mmio_size)
			assert(sizeof(uint8_t) == size);
		assert(BTST(uart_unit->efr, 4) && BTST(uart_unit->mcr, 6));
	}

	const uint32_t data = csx_data_mem_access(&uart_unit->tlr, size, write);

	if(write) {
		if(_trace_mmio_uart) {
			LOG_START("UART Trigger Level Register\n\t");
			LOG_END("RX_FIFO_TRIG_DMA = %02u, TX_FIFO_TRIG_DMA = %02u",
				mlBFEXT(data, 7, 4), mlBFEXT(data, 3, 0));
		}
	}

	return(data);
}

static uint32_t _soc_omap_uart_x1c(void* param, uint32_t ppa, size_t size, uint32_t* write)
{ // spr, tlr, xoff2
	if(_check_pedantic_mmio_size)
		assert(sizeof(uint8_t) == size);

	soc_omap_uart_unit_p uart_unit = __uart_unit(param, ppa);
	
	DEBUG(LOG("lcr = 0x%02x, efr[4] = %1u, mcr[6] = %1u",
		uart_unit->lcr, BEXT(uart_unit->efr, 4), BEXT(uart_unit->mcr, 6)));
	
	if(BTST(uart_unit->efr, 4) && BTST(uart_unit->mcr, 6)) {
			return(_soc_omap_uart_x1c_tlr(param, ppa, size, write));
	} else {
		if(0xbf == uart_unit->lcr) {
			LOG_ACTION(exit(-1));
;//			return(_soc_omap_uart_xoff2(param, ppa, size, write));
		} else {
			return(_soc_omap_uart_x1c_spr(param, ppa, size, write));
		}
	}

	return(0);
}

/* **** */

#define SOC_OMAP_UART_ACLE(_enum, _fn) \
	MMIO_TRACE_FN(0x0000, _enum, 0x0000, 0x0000, _enum, _fn)

static csx_mmio_access_list_t __soc_omap_uart_acl[] = {
	SOC_OMAP_UART_ACLE(_x08, _soc_omap_uart_x08)
	SOC_OMAP_UART_ACLE(_LCR, _soc_omap_uart_lcr)
	SOC_OMAP_UART_ACLE(_x10, _soc_omap_uart_x10)
	SOC_OMAP_UART_ACLE(_x1c, _soc_omap_uart_x1c)
	SOC_OMAP_UART_ACLE(_SCR, _soc_omap_uart_scr)
	SOC_OMAP_UART_ACLE(_SYSC, _soc_omap_uart_sysc)
	SOC_OMAP_UART_ACLE(_SYSS, _soc_omap_uart_syss)
	{ .ppa = ~0U, },
};

/* **** */

soc_omap_uart_p soc_omap_uart_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_uart_h h2uart)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2uart);

	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_omap_uart_p uart = handle_calloc((void**)h2uart, 1, sizeof(soc_omap_uart_t));
	ERR_NULL(uart);

	uart->csx = csx;
	uart->mmio = mmio;

	/* **** */

	csx_mmio_callback_atexit(mmio, &uart->atexit, __soc_omap_uart_atexit, h2uart);
	csx_mmio_callback_atreset(mmio, &uart->atreset, __soc_omap_uart_atreset, uart);

	return(uart);
}

void soc_omap_uart_init(soc_omap_uart_p uart)
{
	ERR_NULL(uart);
	
	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_mmio_p mmio = uart->mmio;

	csx_mmio_register_access_list(mmio, SOC_OMAP_UART1, __soc_omap_uart_acl, uart);
	csx_mmio_register_access_list(mmio, SOC_OMAP_UART2, __soc_omap_uart_acl, uart);
	csx_mmio_register_access_list(mmio, SOC_OMAP_UART3, __soc_omap_uart_acl, uart);
}
