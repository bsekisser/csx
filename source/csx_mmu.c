#include <assert.h>

#include "csx.h"
#include "csx_core.h"

/* **** */

#define LOCAL_RGNDIR "../garmin/rgn_files/"
#define RGNFileName "038201000610"
//#include "../../garmin/rgn_files/038201000610.h"

#define LOCAL_RGNFileName "_loader.bin"
//#define LOCAL_RGNFileName "_firmware.bin"

typedef struct csx_data_t* csx_data_p;
typedef struct csx_data_t {
		uint32_t	base;
		void*		data;
		uint32_t	size;
}csx_data_t;

typedef struct csx_mmu_t* csx_mmu_p;
typedef struct csx_mmu_t {
	csx_p			csx;
	csx_tlb_t		tlb[256];
	csx_data_t		loader;
	csx_data_t		firmware;
	uint8_t			sdram[CSX_SDRAM_SIZE];
	uint8_t			frame_buffer[CSX_FRAMEBUFFER_SIZE];
}csx_mmu_t;

/* **** */

uint32_t csx_data_read(uint8_t* src, uint8_t size)
{
	uint32_t res = 0;

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

void csx_data_write(uint8_t* dst, uint32_t value, uint8_t size)
{
	for(int i = 0; i < size; i++)
	{
		*dst++ = value & 0xff;
		value >>= 8;
	}
}

/* **** */

/*
 * xxxx xxxx | xxxx hhhh | hhhh oooo | oooo oooo	-- 256 entries ***
 * xxxx xxxx | hhhh hhhh | hhhh oooo | oooo oooo	-- 1024 entries
 * xxxx hhhh | hhhh hhhh | hhhh oooo | oooo oooo	-- 64k entries
 */

static void set_tlbe_urwx_rwx(csx_tlb_p t, int ur, int uw, int ux, int r, int w, int x)
{
	t->ur = ur;
	t->uw = uw;
	t->ux = ux;
	t->r = r;
	t->w = w;
	t->x = x;
}

static inline int csx_mmu__tlb_entry(csx_mmu_p mmu, uint32_t va, csx_tlb_h h2tlbe)
{
	if(0) LOG("mmu = 0x%08x, va = 0x%08x, h2tlbe = 0x%08x", (uint)mmu, va, (uint)h2tlbe);

	const uint vp = PAGE(va);
	const uint vp_tlbe = vp & 0xff;

	if(0) LOG("vp = 0x%08x, vp_tlbe = 0x%08x", vp, vp_tlbe);

	csx_tlb_p tlbe = &mmu->tlb[vp_tlbe];

	*h2tlbe = tlbe;

	if(0) LOG("tlbe = 0x%08x", (uint)tlbe);

	if(!tlbe->i || (vp != tlbe->vp)) {
		if(0) LOG("vp = 0x%08x, vp_tlbe = 0x%08x, tlbe = 0x%08x, i = %01u, tlbe->vp = 0x%08x",
			vp, vp_tlbe, (uint)tlbe, tlbe->i, tlbe->vp);
		return(0);
	}

	return(1);
}

static int csx_mmu__tlb_fill(csx_mmu_p mmu, uint32_t va, csx_tlb_p tlbe)
{
	const size_t size = 1;
	
	void* data = 0;
	uint32_t vp = va;
	
	if(_in_bounds(va, size, CSX_SDRAM_BASE, CSX_SDRAM_STOP)) {
		set_tlbe_urwx_rwx(tlbe, 1, 1, 1, 1, 1, 1);
		data = mmu->sdram;
		vp -= CSX_SDRAM_BASE;
	} else if(_in_bounds(va, size, CSX_FRAMEBUFFER_BASE, CSX_FRAMEBUFFER_STOP)) {
		set_tlbe_urwx_rwx(tlbe, 1, 1, 1, 1, 1, 1);
		data = mmu->frame_buffer;
		vp -= CSX_FRAMEBUFFER_BASE;
	} else 
		return(0);

	tlbe->i = 1;
	tlbe->vp = PAGE(va);
	tlbe->data = data + vp;

	return(1);
}

static inline int csx_mmu__tlb_read(csx_mmu_p mmu, uint32_t va, void** data)
{
	csx_tlb_p tlbe = 0;
	
	if(0) LOG("mmu = 0x%08x, va = 0x%08x, data = 0x%08x", (uint)mmu, va, (uint)data);

	if(!csx_mmu__tlb_entry(mmu, va, &tlbe)) {
		if(!csx_mmu__tlb_fill(mmu, va, tlbe))
			return(0);
	}

	if(0) LOG("tlbe->i = %01u, tlbe->vp = 0x%08x, tlbe->r = %01u", tlbe->i, tlbe->vp, tlbe->r);

	if(!tlbe->r)
		return(0);

	*data = tlbe->data;

	return(1);
}

static inline int csx_mmu__tlb_write(csx_mmu_p mmu, uint32_t va, void** data)
{
	csx_tlb_p tlbe = 0;
	
	if(!csx_mmu__tlb_entry(mmu, va, &tlbe)) {
		if(!csx_mmu__tlb_fill(mmu, va, tlbe))
			return(0);
	}

	if(!tlbe->w)
		return(0);

	*data = tlbe->data;

	return(1);
}

/* **** */

int csx_mmu_read(csx_mmu_p mmu, uint32_t va, uint32_t* data, size_t size)
{
	int retval = 1;

	const uint32_t va_page = PAGE(va);
	const uint32_t va_page_size = PAGE(va + (size - 1));

	if(0) LOG("mmu = 0x%08x, va = 0x%08x, data = 0x%08x, size = 0x%08x, va_page = 0x%08x",
		(uint)mmu, va, (uint)data, size, va_page);

	uint count = 0;

	if(1 && (va_page != va_page_size)) {
		LOG("va = 0x%08x (0x%08x, 0x%08x), data = 0x%08x, size = 0x%02x",
			va, va_page, va_page_size, (uint)data, size);

		count = (size |= 0x80);
	}

	void* src = 0;

retry_read:;
	if(csx_mmu__tlb_read(mmu, va, &src)) {
		src += PAGE_OFFSET(va);
		if(!(size & 0x80)) {
			*data = csx_data_read(src, size);
			return(1);
		} else {
			LOG_ACTION(exit(-1));
		}
	}
	
	return(0);
}

int csx_mmu_write(csx_mmu_p mmu, uint32_t va, uint32_t data, size_t size)
{
	int retval = 1;

	const uint32_t va_page = PAGE(va);
	const uint32_t va_page_size = PAGE(va + (size - 1));

	uint count = 0;

	if(1 && (va_page != va_page_size)) {
		LOG("va = 0x%08x (0x%08x, 0x%08x), data = 0x%08x, size = 0x%02x",
			va, va_page, va_page_size, (uint)data, size);

		count = (size |= 0x80);
	}

	void* dst = 0;

retry_write:;
	if(csx_mmu__tlb_write(mmu, va, &dst)) {
		dst += PAGE_OFFSET(va);
		if(!(size & 0x80)) {
			csx_data_write(dst, data, size);
			return(1);
		} else {
			LOG_ACTION(exit(-1));
		}
	}
	
	return(0);
}

int csx_mmu_init(csx_p csx, csx_mmu_h h2mmu)
{
	csx_mmu_p mmu;
	
	ERR_NULL(mmu = malloc(sizeof(csx_mmu_t)));
	if(!mmu)
		return(-1);
	
	memset(mmu, 0, sizeof(csx_mmu_t));
	
	mmu->csx = csx;
	*h2mmu = mmu;
	
	int fd;

	LOG("opening " LOCAL_RGNDIR RGNFileName LOCAL_RGNFileName);

	ERR(fd = open(LOCAL_RGNDIR RGNFileName LOCAL_RGNFileName, O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));
	
	void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);
	
	mmu->loader.base = 0x10020000;
	mmu->loader.data = data;
	mmu->loader.size = sb.st_size;

	const uint32_t base = mmu->loader.base - CSX_SDRAM_BASE;
	memcpy(&mmu->sdram[base], mmu->loader.data, mmu->loader.size);
	
	LOG("base = 0x%08x, data = 0x%08x, size = 0x%08x",
		mmu->loader.base, (uint)mmu->loader.data, mmu->loader.size);
	
	close(fd);

	return(0);
}

