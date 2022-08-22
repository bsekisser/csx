#include "csx.h"

/* **** */

#include <libgen.h>
#include <string.h>

/* **** */

#include "soc.h"
#include "csx_test.h"

/* **** */

const int _check_pedantic_pc = 0;

/* **** */

void _preflight_tests(void)
{
	assert(0x01 == sizeof(uint8_t));
	assert(0x02 == sizeof(uint16_t));
	assert(0x04 == sizeof(uint32_t));
	assert(0x08 == sizeof(uint64_t));
}


int main(int argc, char **argv)
{
	_preflight_tests();

	for(int i = 0; i < argc; i++)
		printf("%s:%s: argv[%d] == %s\n", __FILE__, __FUNCTION__, i, argv[i]);
	
	char *name = basename(argv[0]);
	
	printf("%s:%s: name == %s\n", __FILE__, __FUNCTION__, name);

	int test = 0;
	int core_trace = 0;

	for(int i = 1; i < argc; i++) {
		if(0 == strcmp(argv[i], "-test"))
			test = 1;
		else if(0 == strcmp(argv[i], "-core-trace"))
			core_trace = 1;
	}
	
	if(test)
		return(csx_test_main(core_trace));
	else
		return(csx_soc_main(core_trace));
}
