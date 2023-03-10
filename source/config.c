#include "soc_core_arm.h"

const int _arm_version = arm_v5tej;

const int _check_pedantic_arm_decode_fault = 0;
const int _check_pedantic_mmio = 0;
const int _check_pedantic_pc = 0;
const int _check_pedantic_rname = 0;
const int _check_pedantic_size = 0;

const int _csx_statistical_counters = 1;

const int _csx_counter_sdram = 1;

const int _profile_csx_mem_access = 1;
const int _profile_soc_core_ifetch = 1;
const int _profile_soc_core_read = 1;
const int _profile_soc_core_step = 1;
const int _profile_soc_core_step_arm = 1;
const int _profile_soc_core_step_thumb = 1;
const int _profile_soc_core_write = 1;

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
