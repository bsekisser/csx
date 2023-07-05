#include "soc_core_arm.h"

#define _arm_version arm_v5tej

#define _check_pedantic_arm_decode_fault 0
#define _check_pedantic_mmio 0
#define _check_pedantic_mmio_size 0
#define _check_pedantic_pc 0
#define _check_pedantic_rname 0
#define _check_pedantic_size 0

#define _csx_statistics 0

#define IF_STATISTICS(_x) _csx_statistics ? (_x) : 0
#define _csx_statistical_counters IF_STATISTICS(1)
#define _csx_statistical_profile IF_STATISTICS(0)

#define IF_COUNTERS(_x) (_csx_statistical_counters ? (_x) : 0)

#define IF_PROFILING(_x) (_csx_statistical_profile ? (_x) : 0)
#define _profile_csx_mem_access IF_PROFILING(1)
#define _profile_soc_core_ifetch  IF_PROFILING(1)
#define _profile_soc_core_read IF_PROFILING(1)
#define _profile_soc_core_step IF_PROFILING(1)
#define _profile_soc_core_write IF_PROFILING(1)

#define IF_PROFILING_SOC_CORE_STEP(_x) (_profile_soc_core_step ? (_x) : 0)
#define _profile_soc_core_step_arm IF_PROFILING_SOC_CORE_STEP(1)
#define _profile_soc_core_step_thumb IF_PROFILING_SOC_CORE_STEP(1)

#define _trace_alloc 0
#define _trace_atexit 0
#define _trace_atexit_pedantic 0
#define _trace_atreset 0
#define _trace_bx_0 1
#define _trace_init 0
#define _trace_mem_mmap 0
#define _trace_mem_mmap_alloc 0
#define _trace_mem_mmap_alloc_free 0
#define _trace_mem_mmap_alloc_malloc 0
#define _trace_psr_switch 0

#define _trace_mmio 0

#define IF_TRACE_MMIO(_x) (_trace_mmio ? (_x) : 0)
#define _trace_mmio_cfg IF_TRACE_MMIO(1)
//#define _trace_mmio_dma IF_TRACE_MMIO(1)
#define _trace_mmio_dma 1
#define _trace_mmio_dpll IF_TRACE_MMIO(1)
//#define _trace_mmio_gp_timer IF_TRACE_MMIO(1)
#define _trace_mmio_gp_timer 1
//#define _trace_mmio_lcd IF_TRACE_MMIO(1)
#define _trace_mmio_lcd 1
//#define _trace_mmio_misc IF_TRACE_MMIO(1)
#define _trace_mmio_misc 1
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

#define _use_csx_sdram_mem_access 0
