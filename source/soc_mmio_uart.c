#include "soc_mmio_uart.h"

#include "csx_data.h"
#include "soc_mmio_omap.h"

/* **** */

#include "bitfield.h"
#include "err_test.h"
#include "log.h"

/* **** */

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

enum {
	EFR = 0x08,
	LCR = 0x0c,
	MCR = 0x10,
	SCR = 0x40,
	SPR = 0x1c,
	SYSC = 0x54,
	SYSS = 0x58,
};

csx_data_bit_t SYSC_SoftReset = { SYSC, 2, sizeof(uint8_t) };

csx_data_bit_t SYSS_ResetDone = { SYSS, 0 , sizeof(uint8_t) };

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

	soc_mmio_peripheral(mmio, uart_peripheral, uart);

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
			case EFR:
				LOG_START("UART Enhanced Feature Register\n\t");
				_LOG_("AUTO_CTS_EN: %01u", BEXT(value, 7));
				_LOG_(", AUTO_RTS_EN: %01u", BEXT(value, 6));
				_LOG_(", SPECIAL_CHAR_DETECT: %01u", BEXT(value, 5));
				_LOG_(", ENHANCED_FN: %01u", BEXT(value, 4));
				LOG_END(", SW_FLOW_CONTROL: %01u", mlBFEXT(value, 3, 0));
				break;
			case LCR:
				LOG_START("UART Line Control Register\n\t");
				_LOG_("DIV_EN: %01u", BEXT(value, 7));
				_LOG_(", BREAK_EN: %01u", BEXT(value, 6));
				_LOG_(", PARITY TYPE2: %01u", BEXT(value, 5));
				_LOG_(", PARITY TYPE1: %01u", BEXT(value, 4));
				_LOG_(", PARITY EN: %01u", BEXT(value, 3));
				_LOG_(", NB STOP: %01u", BEXT(value, 2));
				LOG_END(", CHAR_LENGTH: %01u", mlBFEXT(value, 1, 0));
				break;
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
			case SYSC:
				LOG_START("UART System Configuration Register\n\t");
				_LOG_("Reserved: %02u", mlBFEXT(value, 7, 5));
				_LOG_(", IdleMode: %02u", mlBFEXT(value, 4, 3));
				_LOG_(", EnaWakeUp: %01u", BEXT(value, 2));
				_LOG_(", SoftReset: %01u", BEXT(value, 1));
				LOG_END(", AutoIdle: %01u", BEXT(value, 0));
				if(value & 2)
					soc_mmio_peripheral_reset(uart->mmio, uart_peripheral);
				csx_data_bit_clear(data, &SYSC_SoftReset);
				csx_data_bit_set(data, &SYSS_ResetDone);
				break;
		}

		csx_data_write(data + (addr & 0xff), value, size);
	} else {
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}
