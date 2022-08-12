#include "csx.h"
#include "soc_core.h"

const int _check_pedantic_pc = 0;

int csx_soc_init(csx_p csx)
{
	int err;
	
	csx->cycle = 0;
	csx->trace.head = 0;
	csx->trace.tail = 0;
	
	ERR(err = soc_core_init(csx, &csx->core));
	ERR(err = soc_coprocessor_init(csx));
	ERR(err = soc_mmu_init(csx, &csx->mmu));
	ERR(err = soc_mmio_init(csx, &csx->mmio));
	
	soc_mmio_reset(csx->mmio);
	
	return(err);
}

#define Kb(_k) ((_k) * 1024)
#define Mb(_k) Kb((_k) * 1024)

int csx_soc_main(void)
{
	assert(0x01 == sizeof(uint8_t));
	assert(0x02 == sizeof(uint16_t));
	assert(0x04 == sizeof(uint32_t));
	assert(0x08 == sizeof(uint64_t));

#if 0
	printf("0x%08lx -- 0x%08x\n", ~0UL, _BM(0));
	printf("0x%08lx -- 0x%08x\n", ~0UL, _BM(1));
	printf("0x%08lx -- 0x%08x\n", ~0UL, _BM(31));
	printf("0x%08lx -- 0x%08x\n", ~0UL, _BM(32));
	assert(~0UL == _BM(31));
#endif

	int err = 0;
	csx_p csx = 0;
	ERR_NULL(csx = malloc(sizeof(csx_t)));
	if(!csx)
		return(-1);
	
	memset(csx, 0, sizeof(csx_t));
	
	_TRACE_ENABLE_(csx, ENTER);
	_TRACE_ENABLE_(csx, EXIT);
	_TRACE_(csx, ENTER);

//	cs_assert_success(cs_open(CS_ARCH_ARM, mode, &csx->cs_handle));

	ERR(err = csx_soc_init(csx));

//	soc_core_reg_set(csx, rPC, 0x2b5);
//	soc_core_reg_set(csx->core, rPC, CSX_SDRAM_BASE);
	
	soc_core_p core = csx->core;

	if(!err)
	{
		csx->state = CSX_STATE_RUN;
		
		int limit = Mb(2) + Kb(0) + Kb(0);
		for(int i = 0; i < limit; i++)
		{
			csx->cycle++;

			core->step(core);

			if((csx->state & CSX_STATE_HALT) || (0 == PC))
			{
				i = limit;
				LOG_ACTION(break);
			}
		}
	}

//	cs_close(&handle);

	LOG("0x%08x", IP);

	_TRACE_(csx, EXIT);

	return(err);
}

uint32_t csx_soc_read(csx_p csx, uint32_t va, size_t size)
{
	uint32_t data = 0;
	
	if(soc_mmu_read(csx->mmu, va, &data, size))
		;
	else if(_in_bounds(va, size, CSX_MMIO_BASE, CSX_MMIO_STOP))
		data = soc_mmio_read(csx->mmio, va, size);
	
	return(data);
}

void csx_soc_write(csx_p csx, uint32_t va, uint32_t data, size_t size)
{
	if(soc_mmu_write(csx->mmu, va, data, size))
		;
	else if(_in_bounds(va, size, CSX_MMIO_BASE, CSX_MMIO_STOP))
		soc_mmio_write(csx->mmio, va, data, size);
}

int main(int argc, char **argv)
{
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
		return(csx_test_main());
	else
		return(csx_soc_main(/*core_trace*/));
}
