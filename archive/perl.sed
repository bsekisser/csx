s/csx_coprocessor/soc_coprocessor/g
s/csx_coproc_data/soc_coprocessor/g
s/csx_core/soc_core/g
s/csx_core_p/soc_core_p/g
s/csx_core_write/soc_core_write/g
s/csx_data_read/soc_data_read/g
s/csx_data_write/soc_data_write/g
s/csx_dpi/soc_core_dpi/g
s/csx_ldst/soc_core_ldst/g
s/csx_mmu/soc_mmu/g
s/csx_mmio/soc_mmio/g
s/csx_msr/soc_core_msr/g
s/csx_psr/soc_core_psr/g
s/CSX_PSR/SOC_PSR/g
s/csx_reg/soc_core_reg/g
s/csx_tlb/soc_mmu_tlb/g
s/csx_trace_inst/soc_core_trace_inst/g
s/csx_trace_psr/soc_core_trace_psr/g

s/CSX_CORE_ARM/SOC_CORE_ARM/g
s/CSX_CORE_THUMB/SOC_CORE_THUMB/g

perl -i -pe 's/old/new/g' *
