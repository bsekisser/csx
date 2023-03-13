#include "soc_core_arm.h"

#define _arm_version arm_v5tej

#define _check_pedantic_arm_decode_fault 0
#define _check_pedantic_mmio 0
#define _check_pedantic_pc 0
#define _check_pedantic_rname 0
#define _check_pedantic_size 0

#define _csx_statistics 0

#define IF_STATISTICS(_x) _csx_statistics ? (_x) : 0
#define _csx_statistical_counters IF_STATISTICS(1)
#define _csx_statistical_profile IF_STATISTICS(0)

#define IF_COUNTERS(_x) (_csx_statistical_counters ? (_x) : 0)
#define _csx_counter_sdram IF_COUNTERS(1)

#define IF_PROFILING(_x) (_csx_statistical_profile ? (_x) : 0)
#define _profile_csx_mem_access IF_PROFILING(1)
#define _profile_soc_core_ifetch  IF_PROFILING(1)
#define _profile_soc_core_read IF_PROFILING(1)
#define _profile_soc_core_step IF_PROFILING(1)
#define _profile_soc_core_write IF_PROFILING(1)

#define IF_PROFILING_SOC_CORE_STEP(_x) (_profile_soc_core_step ? (_x) : 0)
#define _profile_soc_core_step_arm IF_PROFILING_SOC_CORE_STEP(1)
#define _profile_soc_core_step_thumb IF_PROFILING_SOC_CORE_STEP(1)

#define _trace_atexit 0
#define _trace_atreset 0
#define _trace_init 0
#define _trace_mem_mmap 0
#define _trace_mem_mmap_alloc 0
#define _trace_mem_mmap_alloc_free 0
#define _trace_mem_mmap_alloc_malloc 0

#define _trace_mmio 0

#define _use_csx_mem_access 1
#define _use_csx_sdram_mem_access 0
