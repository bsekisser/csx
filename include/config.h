#pragma once

/* **** */

#define _check_pedantic_mmio 0
#define _check_pedantic_mmio_size 0

#define _csx_statistics 0

#define IF_STATISTICS(_x) _csx_statistics ? (_x) : 0
#define _csx_statistical_counters IF_STATISTICS(1)
#define _csx_statistical_profile IF_STATISTICS(0)

#define IF_COUNTERS(_x) (_csx_statistical_counters ? (_x) : 0)

#define IF_PROFILING(_x) (_csx_statistical_profile ? (_x) : 0)

#define _trace_mmio 0

#define IF_TRACE_MMIO(_x) (_trace_mmio ? (_x) : 0)
#define _trace_mmio_cfg IF_TRACE_MMIO(1)
#define _trace_mmio_dma IF_TRACE_MMIO(1)
#define _trace_mmio_dma_lcd IF_TRACE_MMIO(1)
#define _trace_mmio_dpll IF_TRACE_MMIO(1)
#define _trace_mmio_gp_timer IF_TRACE_MMIO(1)
#define _trace_mmio_lcd IF_TRACE_MMIO(1)
#define _trace_mmio_misc IF_TRACE_MMIO(1)
#define _trace_mmio_mpu IF_TRACE_MMIO(1)
#define _trace_mmio_mpu_gpio IF_TRACE_MMIO(1)
#define _trace_mmio_mpu_ihr IF_TRACE_MMIO(1)
#define _trace_mmio_mpu_timer IF_TRACE_MMIO(1)
#define _trace_mmio_os_timer IF_TRACE_MMIO(1)
#define _trace_mmio_tc_emiff IF_TRACE_MMIO(1)
#define _trace_mmio_tc_emifs IF_TRACE_MMIO(1)
#define _trace_mmio_tc_ocp IF_TRACE_MMIO(1)
#define _trace_mmio_usb_client IF_TRACE_MMIO(1)
#define _trace_mmio_uart IF_TRACE_MMIO(1)
#define _trace_mmio_watchdog IF_TRACE_MMIO(1)
