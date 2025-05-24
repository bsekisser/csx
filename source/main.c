#include "csx_soc.h"
#include "csx.h"

#include "csx_armvm_glue.h"

/* **** local includes */

#include "libbse/include/action.h"
#include "libbse/include/dtime.h"
#include "libbse/include/err_test.h"
#include "libbse/include/log.h"

/* **** system includes */

#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdint.h>
#include <string.h>

/* **** */

static void _preflight_tests(void)
{
	assert(-1U == ~0U);
	assert(1 == (0 == 0));
	assert(0 == (0 != 0));
	assert(1 == !!1);
	assert(0 == !!0);
	assert(1 == !!-1);
	assert(1 == !!0x12345678);
	assert(1 == !!0x87654321);
	assert(0x01 == sizeof(uint8_t));
	assert(0x02 == sizeof(uint16_t));
	assert(0x04 == sizeof(uint32_t));
	assert(0x08 == sizeof(uint64_t));
	assert(sizeof(uint32_t) <= sizeof(signed));
	assert(sizeof(uint32_t) <= sizeof(unsigned));

#if 0
	/*
	 * https://stackoverflow.com/a/60023331
	 *
	 * >> x promoted to signed int
	 */

	uint16_t x = 0xf123;
	uint32_t y = (x << 16) >> 16;

	LOG("x = 0x%08x, y = 0x%08x", x, y);

	assert(x == y);
#endif

	for(int i = 1; i < 32; i++) {
		uint32_t check1 = (32 - i);
		uint32_t check2 = (-i & 31);
		if(0) LOG("((32 - i) == (-i & 31)) -- (0x%08x, 0x%08x)",
			check1, check2);
		assert(check1 == check2);
	}
}

int main(int argc, char **argv)
{
//	action_log.raw_flags = ~0U;

	_preflight_tests();

	if(argc) for(int i = 0; i < argc; i++)
		printf("%s:%s: argv[%d] == %s\n", __FILE__, __FUNCTION__, i, argv[i]);

	if(argc) {
		char *name = basename(argv[0]);

		printf("%s:%s: name == %s\n", __FILE__, __FUNCTION__, name);
	}

	int core_trace = 0;
	int loader_firmware = 0;

	for(int i = 1; i < argc; i++) {
		if(0 == strcmp(argv[i], "-core-trace"))
			core_trace = 1;
		else if(0 == strcmp(argv[i], "-firmware"))
			loader_firmware = 1;
	}

	const uint64_t dtime_second = dtime_calibrate();
	const double dtime_second_ratio = 1.0 / dtime_second;

	csx_ref csx = csx_alloc(0);
	int err = 0;

//	err |= csx_action(0, (void*)&csx, _ACTION_ALLOC);
	err |= csx_action(err, csx, _ACTION_ALLOC_INIT);
	err |= csx_action(err, csx, _ACTION_INIT);
	err |= csx_action(err, csx, _ACTION_RESET);

	const uint64_t dtime_start = get_dtime();

	csx_soc_main(csx, core_trace, loader_firmware);

	const uint64_t dtime_end = get_dtime();
	const uint64_t dtime_run = dtime_end - dtime_start;

	const uint64_t cycle = CYCLE;
	const uint64_t icount = ICOUNT;

	const uint64_t dtime_cycle = dtime_run / cycle;
	const uint64_t dtime_insn = dtime_run / icount;

	LOG_ERR("cycles = 0x%016" PRIx64 ", insns = 0x%016" PRIx64,
		cycle, icount);
	LOG_ERR("dtime_start = 0x%016" PRIx64 ", dtime_end = 0x%016" PRIx64 ", dtime_run = 0x%016" PRIx64,
		dtime_start, dtime_end, dtime_run);
	LOG_ERR("dtime/cycle = 0x%016" PRIx64 ", dtime/insn = 0x%016" PRIx64,
		dtime_cycle, dtime_insn);

	LOG_ERR("\n\n");

	const double kips_ratio = 1.0 / KHz(1.0);
	const double mips_ratio = 1.0 / MHz(1.0);

	LOG_ERR("kips_ratio = %016f", kips_ratio);
	LOG_ERR("mips_ratio = %016f", mips_ratio);

	const double seconds = dtime_run * dtime_second_ratio;
	const uint64_t icount_second = icount / seconds;

	LOG_ERR("seconds --- %0.016f", seconds);

	LOG_ERR("    dtime_run --- 0x%016" PRIx64, dtime_run);
	LOG_ERR(" dtime/second --- 0x%016" PRIx64, dtime_second);
	LOG_ERR("icount/second --- 0x%016" PRIx64, icount_second);

	if(icount_second < MHz(1)) {
		LOG_ERR("est kips = %0.16f", icount_second * kips_ratio);
	} else {
		LOG_ERR("est mips = %0.16f", icount_second * mips_ratio);
	}

	err |= csx_action(err, csx, _ACTION_EXIT);
	(void)argc, (void)argv;
}
