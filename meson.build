project('csx', 'c')

inc = include_directories('include', '../../include')

capstone = dependency('capstone')

csx_sources = [
	'source/csx.c',
	'source/csx_core.c',
	'source/csx_mmio.c',
	'source/csx_mmu.c'
	]
	
executable(
	'csx',
	csx_sources,
	include_directories: inc)
