#pragma once

extern const int _arm_version;

extern const int _check_pedantic_arm_decode_fault;
extern const int _check_pedantic_mmio;
extern const int _check_pedantic_pc;
extern const int _check_pedantic_rname;
extern const int _check_pedantic_size;

extern const int _csx_counter_sdram;
extern const int _csx_statistical_counters;

extern const int _profile_csx_mem_access;
extern const int _profile_soc_core_ifetch;
extern const int _profile_soc_core_read;
extern const int _profile_soc_core_step;
extern const int _profile_soc_core_step_arm;
extern const int _profile_soc_core_step_thumb;
extern const int _profile_soc_core_write;

extern const int _trace_atexit;
extern const int _trace_atreset;
extern const int _trace_init;
extern const int _trace_mem_mmap;
extern const int _trace_mem_mmap_alloc;
extern const int _trace_mem_mmap_alloc_free;
extern const int _trace_mem_mmap_alloc_malloc;

extern const int _trace_mmio;

extern const int _use_csx_mem_access;
extern const int _use_csx_sdram_mem_access;

#define CSX_COUNTERS(_x)
#define CSX_PROFILE(_x)
