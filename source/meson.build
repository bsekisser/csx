capstone = dependency('capstone')

subdir('core')

csx_sources = [
	'csx.c',
	]

csx_test_sources = [
	'csx_test.c',
	'test/csx_test_arm.c',
	'test/csx_test_arm_inst.c',
	]

executable(
	'csx',
	csx_sources,
	include_directories: inc,
	link_with: csx_lib_core,
	)

executable(
	'csx_test',
	'test/csx_test_arm.c',
	csx_test_sources,
	include_directories: inc,
	link_with: csx_lib_core,
	)
