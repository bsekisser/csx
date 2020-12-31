#include <assert.h>

typedef struct csx_test_t* csx_test_p;
typedef struct csx_test_t {
	csx_p			csx;
	csx_core_p		core;
	
	uint32_t		pc;
	
	T(uint32_t		trace_flags);
}csx_test_t;

void csx_test_run(csx_test_p t, uint32_t start_pc, uint32_t end_pc, uint32_t count);

