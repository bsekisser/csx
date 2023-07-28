#include "csx_soc.h"
#include "csx_test.h"
#include "csx.h"

/* **** local includes */

#include "dtime.h"
#include "err_test.h"
#include "log.h"

/* **** system includes */

#include <errno.h>
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
	_preflight_tests();

	for(int i = 0; i < argc; i++)
		printf("%s:%s: argv[%d] == %s\n", __FILE__, __FUNCTION__, i, argv[i]);

	char *name = basename(argv[0]);

	printf("%s:%s: name == %s\n", __FILE__, __FUNCTION__, name);

	int core_trace = 0;
	int loader_firmware = 0;
	int test = 0;

	for(int i = 1; i < argc; i++) {
		if(0 == strcmp(argv[i], "-core-trace"))
			core_trace = 1;
		else if(0 == strcmp(argv[i], "-firmware"))
			loader_firmware = 1;
		else if(0 == strcmp(argv[i], "-test"))
			test = 1;
	}

	uint64_t est_host_cps = dtime_calibrate();

	csx_p csx = csx_init(csx_alloc());

	csx_reset(csx);

	uint64_t dtime_start = get_dtime();

	if(test)
		csx_test_main(csx, core_trace);
	else
		csx_soc_main(csx, core_trace, loader_firmware);

	uint64_t dtime_end = get_dtime();
	uint64_t dtime_run = dtime_end - dtime_start;

	uint64_t dtime_cycle = dtime_run / csx->cycle;
	uint64_t dtime_insn = dtime_run / csx->insns;

	LOG_ERR("cycles = 0x%016" PRIx64 ", insns = 0x%016" PRIx64,
		csx->cycle, csx->insns);
	LOG_ERR("dtime_start = 0x%016" PRIx64 ", dtime_end = 0x%016" PRIx64 ", dtime_run = 0x%016" PRIx64,
		dtime_start, dtime_end, dtime_run);
	LOG_ERR("dtime/cycle = 0x%016" PRIx64 ", dtime/insn = 0x%016" PRIx64,
		dtime_cycle, dtime_insn);

	double ratio = 1.0 / est_host_cps;
//	double ratio = (double)dtime_run / est_host_cps;

	double dcrt = (double)csx->cycle / dtime_run;

	LOG_ERR("\n\n");
	LOG_ERR("est_host_cps = 0x%016" PRIx64, est_host_cps);
	LOG_ERR("ratio --- %0.05f", ratio);
	LOG_ERR("cycle --- %0.05f", ratio * dtime_cycle);
	LOG_ERR("insn --- %0.05f", ratio * dtime_insn);
	LOG_ERR("dcrt -- %0.05f, dcrt*host --- %0.05f", dcrt, ratio * dcrt);
	
	csx_atexit(&csx);
}
