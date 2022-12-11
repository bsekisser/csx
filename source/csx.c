#include "csx.h"

/* **** */

#include <libgen.h>
#include <string.h>

/* **** */

#include "soc.h"
#include "soc_core_arm.h"
#include "csx_test.h"

/* **** */

#include "dtime.h"
#include "log.h"

/* **** */

const int _arm_version = arm_v5tej;

const int _check_pedantic_mmio = 0;
const int _check_pedantic_pc = 0;

/* **** */

void _preflight_tests(void)
{
	assert(0x01 == sizeof(uint8_t));
	assert(0x02 == sizeof(uint16_t));
	assert(0x04 == sizeof(uint32_t));
	assert(0x08 == sizeof(uint64_t));

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

//	dtime_calibrate(void);

	csx_p csx = 0;

	uint64_t dtime_start = get_dtime();
	
	if(test)
		csx_test_main(&csx, core_trace);
	else
		csx_soc_main(&csx, core_trace, loader_firmware);
	
	uint64_t dtime_end = get_dtime();
	uint64_t dtime_run = dtime_end - dtime_start;
	
	uint64_t dtime_cycle = dtime_run / csx->cycle;
	uint64_t dtime_insn = dtime_run / csx->insns;
	
	LOG("cycles = 0x%016llx, insns = 0x%016llx",
		csx->cycle, csx->insns);
	LOG("dtime_start = 0x%016llx, dtime_end = 0x%016llx, dtime_run = 0x%016llx",
		dtime_start, dtime_end, dtime_run);
	LOG("dtime/cycle = 0x%016llx, dtime/insn = 0x%016llx",
		dtime_cycle, dtime_insn);
}
