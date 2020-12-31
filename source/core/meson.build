csx_core_sources = [
	'csx_core.c',
	'csx_core_decode.c',
	'csx_core_psr.c',
	'csx_core_reg.c',
	'csx_mmio.c',
	'csx_mmu.c',
	'csx_coprocessor.c',
#	'omap1.c'
	]


csx_core_arm_sources = [
	'csx_core_arm.c',
	]

csx_core_thumb_sources = [
	'csx_core_thumb.c',
	]

csx_core_trace_sources = [
	'csx_core_disasm.c',
	'csx_core_trace.c',
	]


csx_lib_core_arm = static_library(
	'_csx_core_arm',
	csx_core_arm_sources,
	include_directories: inc,
	)

csx_lib_core_thumb = static_library(
	'_csx_core_thumb',
	csx_core_thumb_sources,
	include_directories: inc,
	)


csx_lib_core = shared_library(
	'_csx_core',
	[ csx_core_sources, csx_core_trace_sources ],
	include_directories: inc,
	link_with: [
		csx_lib_core_arm,
		csx_lib_core_thumb,
		],
	dependencies: [ capstone ])
