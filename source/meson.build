capstone = dependency('capstone')

subdir('core')
subdir('soc')

csx_sources = [
	'csx.c',
	]

csx_test_sources = [
	'csx_test.c',
	'test/csx_test_utility.c',
	'test/csx_test_arm.c',
	'test/csx_test_arm_inst.c',
	'test/csx_test_thumb.c',
	'test/csx_test_thumb_inst.c',
	]

executable(
	'csx',
	csx_sources,
	include_directories: inc,
	link_with: [ csx_lib_soc, csx_lib_core ],
	)

executable(
	'csx_test',
	csx_test_sources,
	include_directories: inc,
	link_with: [ csx_lib_soc, csx_lib_core ],
	)
