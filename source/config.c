#include "soc_core_arm.h"

const int _arm_version = arm_v5tej;

const int _check_pedantic_arm_decode_fault = 0;
const int _check_pedantic_mmio = 0;
const int _check_pedantic_pc = 0;
const int _check_pedantic_rname = 0;
const int _check_pedantic_size = 0;

const int _csx_statistics = 0;

#define IF_STATISTICS(_x) _csx_statistics ? (_x) : 0
const int _csx_statistical_counters = IF_STATISTICS(1);
const int _csx_statistical_profile = IF_STATISTICS(0);

#define IF_COUNTERS(_x) (_csx_statistical_counters ? (_x) : 0)
const int _csx_counter_sdram = IF_COUNTERS(1);

#define IF_PROFILING(_x) (_csx_statistical_profile ? (_x) : 0)
const int _profile_csx_mem_access = IF_PROFILING(1);
const int _profile_soc_core_ifetch =  IF_PROFILING(1);
const int _profile_soc_core_read = IF_PROFILING(1);
const int _profile_soc_core_step = IF_PROFILING(1);
const int _profile_soc_core_write = IF_PROFILING(1);

#define IF_PROFILING_SOC_CORE_STEP(_x) (_profile_soc_core_step ? (_x) : 0)
const int _profile_soc_core_step_arm = IF_PROFILING_SOC_CORE_STEP(1);
const int _profile_soc_core_step_thumb = IF_PROFILING_SOC_CORE_STEP(1);

const int _trace_atexit = 1;
const int _trace_atreset = 1;
const int _trace_init = 1;
const int _trace_mem_mmap = 1;
const int _trace_mem_mmap_alloc = 1;
const int _trace_mem_mmap_alloc_free = 1;
const int _trace_mem_mmap_alloc_malloc = 1;

const int _trace_mmio = 0;

const int _use_csx_mem_access = 1;
const int _use_csx_sdram_mem_access = 0;
