#include "csx.h"
#include "csx_mmio.h"

enum {
	MEM_READ_BIT = 0,
	MEM_WRITE_BIT,
	MEM_TRACE_READ_BIT,
	MEM_TRACE_WRITE_BIT,
};

#define MEM_READ (1 << MEM_READ_BIT)
#define MEM_WRITE (1 << MEM_WRITE_BIT)
#define MEM_READ_TRACE (1 << MEM_TRACE_READ_BIT)
#define MEM_WRITE_TRACE (1 << MEM_TRACE_WRITE_BIT)

#define MEM_RW (MEM_READ | MEM_WRITE)

#define MEM_TRACE_RW (MEM_READ_TRACE | MEM_WRITE_TRACE)

#define MEM_R_TRACE_R (MEM_READ | MEM_READ_TRACE)
#define MEM_RW_TRACE_RW (MEM_RW | MEM_TRACE_RW)

#define MMIO_LIST \
	MMIO(0xfffb, 0x4018, 0x0000, 0x0000, 16, MEM_RW, USB_CLNT_SYSCON1) \
	\
	\
	MMIO(0xfffe, 0x100c, 0x0000, 0x0000, 32, MEM_RW, COMP_MODE_CTRL_0) \
	MMIO(0xfffe, 0x1038, 0x0000, 0x0000, 32, MEM_RW, FUNC_MUX_CTRL_D) \
	MMIO(0xfffe, 0x1060, 0x0000, 0x0000, 32, MEM_RW, VOLTAGE_CTRL_0) \
	MMIO(0xfffe, 0x1110, 0x0000, 0x0000, 32, MEM_RW, MOD_CONF_CTRL_1) \
	MMIO(0xfffe, 0x1140, 0x0000, 0x007f, 32, MEM_RW, RESET_CTL) \
	MMIO(0xfffe, 0x1160, 0x0000, 0x0000, 32, MEM_TRACE_RW, x0xfffe_0x1160) \
	\
	MMIO(0xfffe, 0xb034, 0x0000, 0x0000, 32, MEM_RW, WWPS) \
	MMIO(0xfffe, 0xb048, 0x0000, 0x0000, 32, MEM_RW, WSPR) \
	\
	MMIO(0xfffe, 0xc700, 0x0000, 0x0000, 32, MEM_RW, MPU_CNTL_TIMER_3) \
	MMIO(0xfffe, 0xc704, 0x0000, 0x0000, 32, MEM_WRITE, MPU_LOAD_TIM_3) \
	MMIO(0xfffe, 0xc708, 0x0000, 0x0000, 32, MEM_R_TRACE_R, MPU_READ_TIM_3) \
	\
	MMIO(0xfffe, 0xc808, 0x0000, 0x8000, 16, MEM_RW, MPU_TIMER_MODE_WD) \
	\
	MMIO(0xfffe, 0xcc14, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS1_CONFIG) \
	MMIO(0xfffe, 0xcc18, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS2_CONFIG) \
	MMIO(0xfffe, 0xcc1c, 0x0000, 0x0000, 32, MEM_RW, EMIFS_CS3_CONFIG) \
	MMIO(0xfffe, 0xcc50, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS0_CONFIG) \
	MMIO(0xfffe, 0xcc54, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS1_CONFIG) \
	MMIO(0xfffe, 0xcc58, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS2_CONFIG) \
	MMIO(0xfffe, 0xcc5c, 0x0000, 0x0000, 32, MEM_RW, EMIFS_ADV_CS3_CONFIG) \
	\
	MMIO(0xfffe, 0xce00, 0x0000, 0x3000, 32, MEM_RW, ARM_CKCTL) \
	MMIO(0xfffe, 0xce04, 0x0000, 0x0400, 32, MEM_RW, ARM_IDLECT1) \
	MMIO(0xfffe, 0xce08, 0x0000, 0x0100, 32, MEM_RW, ARM_IDLECT2) \
	MMIO(0xfffe, 0xce14, 0x0000, 0x0000, 32, MEM_RW, ARM_RSTCT2) \
	MMIO(0xfffe, 0xce18, 0x0000, 0x0038, 32, MEM_RW, ARM_SYSST) \
	\
	MMIO(0xfffe, 0xcf00, 0x0000, 0x2002, 32, MEM_RW, DPLL1_CTL_REG)

#undef MMIO
#define MMIO(_ahi, _alo, _dhi, _dlo, _size, _access, _name) \
	_name = ((_ahi ## ULL << 16) + _alo ## ULL),

enum {
	MMIO_LIST
};

typedef struct ea_trace_t* ea_trace_p;
typedef struct ea_trace_t {
	uint32_t	address;
	uint32_t	reset_value;
	uint8_t		size;
	uint32_t	access;
	const char *name;
}ea_trace_t;

#undef MMIO
#define MMIO(_ahi, _alo, _dhi, _dlo, _size, _access, _name) \
	{ ((_ahi ## ULL << 16) | _alo ## ULL), \
		((_dhi ## ULL << 16) | _dlo ## ULL), \
		((_size) >> 3), _access, #_name, },
	
static struct ea_trace_t trace_list[] = {
	MMIO_LIST
	{ 0ULL,0ULL,0,0UL,0 }
};

ea_trace_p omap_mmio_get_trace(uint64_t address)
{
	int i = 0;
	do {
		ea_trace_p tl = &trace_list[i++];

		if(tl->address == address)
			return(tl);
		if(0 == tl->address)
			return(0);
	}while(trace_list[i].address);

	return(0);
}

typedef struct csx_mmio_t* csx_mmio_p;
typedef struct csx_mmio_t {
	csx_p		csx;
	uint8_t		data[CSX_MMIO_SIZE];
	uint8_t		data_size;
	uint64_t	timer_base[4];
}csx_mmio_t;

uint32_t csx_mmio_read(csx_mmio_p mmio, uint32_t vaddr, uint8_t size)
{
	csx_p csx = mmio->csx;
	
	ea_trace_p eat = omap_mmio_get_trace(vaddr);
	const char *name = eat ? eat->name : "";
	
	uint32_t paddr = vaddr - CSX_MMIO_BASE;
	
	LOG("cycle = 0x%016llx, vaddr = 0x%08x, paddr = 0x%08x, name = %s", mmio->csx->cycle, vaddr, paddr, name);
	
	if(!eat)
		LOG_ACTION(exit(1));

	if(vaddr >= CSX_MMIO_BASE && vaddr <= CSX_MMIO_STOP)
	{
		uint8_t value_size = eat ? eat->size : 4;
		uint32_t value = csx_data_read(&mmio->data[paddr], value_size);

		switch(vaddr)
		{
			case MPU_READ_TIM_3:
				value = csx->cycle - mmio->timer_base[3];
				csx_data_write(&mmio->data[paddr], value, value_size);
				break;
		}
		
		return(csx_data_read((uint8_t*)&value, size));
	}

	LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_READ));
	
	return(0);
}

void csx_mmio_write(csx_mmio_p mmio, uint32_t vaddr, uint32_t value, uint8_t size)
{
	csx_p csx = mmio->csx;
	
	ea_trace_p eat = omap_mmio_get_trace(vaddr);
	const char* name = eat ? eat->name :  "";

	uint32_t paddr = vaddr - CSX_MMIO_BASE;

	LOG("cycle = 0x%016llx, vaddr = 0x%08x, paddr = 0x%08x, value = 0x%08x, name = %s",
		csx->cycle, vaddr, paddr, value, name);

	if(!eat)
		LOG_ACTION(exit(1));

	if(vaddr >= CSX_MMIO_BASE && vaddr <= CSX_MMIO_STOP)
	{
		uint8_t value_size = eat ? eat->size : 4;
		
		switch(vaddr)
		{
			case DPLL1_CTL_REG:
				value |= 1;
				break;
			case MPU_LOAD_TIM_3:
				mmio->timer_base[3] = csx->cycle;
				csx_mmio_write(mmio, MPU_READ_TIM_3, value, value_size);
				break;
		}
		
		csx_data_write(&mmio->data[paddr], value, value_size);
	}
	else
	{
		LOG_ACTION(csx->state |= (CSX_STATE_HALT | CSX_STATE_INVALID_WRITE));
	}
}

int csx_mmio_init(csx_p csx, csx_mmio_h h2mmio)
{
	csx_mmio_p mmio;
	
	ERR_NULL(mmio = malloc(sizeof(csx_mmio_t)));
	if(!mmio)
		return(-1);

	mmio->csx = csx;
	*h2mmio = mmio;
	
	int i = 0;
	do {
		ea_trace_p te = &trace_list[i++];
		
		uint32_t paddr = te->address - CSX_MMIO_BASE;

		LOG("[0x%08x, 0x%08x] = 0x%08x, size = 0x%02x, access = 0x%04x, name: %s",
			te->address, paddr, te->reset_value, te->size, te->access, te->name);
		
		csx_data_write(&mmio->data[paddr], te->reset_value, te->size);
	}while(trace_list[i].address);

	return(0);
}
