#include "soc_mmu.h"

/* **** */

#include "bounds.h"
#include "err_test.h"
#include "log.h"
#include "page.h"

/* **** */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

typedef struct soc_mmu_t* soc_mmu_p;
typedef struct soc_mmu_t {
	csx_p			csx;
	soc_mmu_tlb_t		tlb[256];
	csx_data_t		loader;
	csx_data_t		firmware;
	uint8_t			sdram[CSX_SDRAM_SIZE];
	uint8_t			frame_buffer[CSX_FRAMEBUFFER_SIZE];
}soc_mmu_t;

/* **** */

uint32_t soc_data_read(void* p2src, uint8_t size)
{
	uint32_t res = 0;

	uint8_t* src = (uint8_t*)p2src;

	for(int i = 0; i < size; i++)
		res |= ((*src++) << (i << 3));

	return(res);
}

void soc_data_write(void* p2dst, uint32_t value, uint8_t size)
{
	uint8_t* dst = (uint8_t*)p2dst;
	
	for(int i = 0; i < size; i++)
		*dst++ = value >> (i << 3) & 0xff;
}

/* **** */

/*
 * xxxx xxxx | xxxx hhhh | hhhh oooo | oooo oooo	-- 256 entries ***
 * xxxx xxxx | hhhh hhhh | hhhh oooo | oooo oooo	-- 1024 entries
 * xxxx hhhh | hhhh hhhh | hhhh oooo | oooo oooo	-- 64k entries
 */

static void set_tlbe_urwx_rwx(soc_mmu_tlb_p t, int ur, int uw, int ux, int r, int w, int x)
{
	t->ur = ur;
	t->uw = uw;
	t->ux = ux;
	t->r = r;
	t->w = w;
	t->x = x;
}

void soc_mmu_tlb_invalidate(soc_mmu_p mmu)
{
	for(int i = 0; i < 256; i++)
		memset(&mmu->tlb[i], 0, sizeof(soc_mmu_tlb_t));
}

static inline int soc_mmu__tlb_entry(soc_mmu_p mmu, uint32_t va, soc_mmu_tlb_h h2tlbe)
{
	if(0) LOG("mmu = 0x%08x, va = 0x%08x, h2tlbe = 0x%08x", (uint)mmu, va, (uint)h2tlbe);

	const uint vp = PAGE(va);
	const uint vp_tlbe = vp & 0xff;

	if(0) LOG("vp = 0x%08x, vp_tlbe = 0x%08x", vp, vp_tlbe);

	soc_mmu_tlb_p tlbe = &mmu->tlb[vp_tlbe];

	*h2tlbe = tlbe;

	if(0) LOG("tlbe = 0x%08x", (uint)tlbe);

	if(!tlbe->i || (vp != tlbe->vp)) {
		if(0) LOG("vp = 0x%08x, vp_tlbe = 0x%08x, tlbe = 0x%08x, i = %01u, tlbe->vp = 0x%08x",
			vp, vp_tlbe, (uint)tlbe, tlbe->i, tlbe->vp);
		return(0);
	}

	return(1);
}

static int soc_mmu__tlb_fill(soc_mmu_p mmu, uint32_t va, soc_mmu_tlb_p tlbe)
{
	const size_t size = 1;
	
	void* data = 0;
	uint32_t vpo = va;
	
	if(_in_bounds(va, size, CSX_SDRAM_BASE, CSX_SDRAM_STOP)) {
		set_tlbe_urwx_rwx(tlbe, 1, 1, 1, 1, 1, 1);
		data = mmu->sdram;
		vpo -= CSX_SDRAM_BASE;
	} else if(_in_bounds(va, size, CSX_FRAMEBUFFER_BASE, CSX_FRAMEBUFFER_STOP)) {
		set_tlbe_urwx_rwx(tlbe, 1, 1, 1, 1, 1, 1);
		data = mmu->frame_buffer;
		vpo -= CSX_FRAMEBUFFER_BASE;
	} else 
		return(0);

	tlbe->i = 1;
	tlbe->vp = PAGE(va);
	tlbe->data = data + (vpo & PAGE_MASK);

	return(1);
}

static inline int soc_mmu__tlb_read(soc_mmu_p mmu, uint32_t va, void** data)
{
	soc_mmu_tlb_p tlbe = 0;
	
	if(0) LOG("mmu = 0x%08x, va = 0x%08x, data = 0x%08x", (uint)mmu, va, (uint)data);

	if(!soc_mmu__tlb_entry(mmu, va, &tlbe))	{
		if(!soc_mmu__tlb_fill(mmu, va, tlbe))
			return(0);
	}

	if(0) LOG("tlbe->i = %01u, tlbe->vp = 0x%08x, tlbe->r = %01u", tlbe->i, tlbe->vp, tlbe->r);

	if(!tlbe->r)
		return(0);

	*data = tlbe->data;

	return(1);
}

static inline int soc_mmu__tlb_write(soc_mmu_p mmu, uint32_t va, void** data)
{
	soc_mmu_tlb_p tlbe = 0;
	
	if(!soc_mmu__tlb_entry(mmu, va, &tlbe)) {
		if(!soc_mmu__tlb_fill(mmu, va, tlbe))
			return(0);
	}

	if(!tlbe->w)
		return(0);

	*data = tlbe->data;

	return(1);
}

/* **** */

int soc_mmu_read(soc_mmu_p mmu, uint32_t va, uint32_t* data, size_t size)
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
	if(soc_mmu__tlb_read(mmu, va, &src)) {
		src += PAGE_OFFSET(va);
		if(!(size & 0x80)) {
			*data = soc_data_read(src, size);
			return(1);
		} else {
			LOG_ACTION(exit(-1));
		}
	}
	
	return(0);
}

int soc_mmu_write(soc_mmu_p mmu, uint32_t va, uint32_t data, size_t size)
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
	if(soc_mmu__tlb_write(mmu, va, &dst)) {
		dst += PAGE_OFFSET(va);
		if(!(size & 0x80)) {
			soc_data_write(dst, data, size);
			return(1);
		} else {
			LOG_ACTION(exit(-1));
		}
	}
	
	return(0);
}

int soc_mmu_init(csx_p csx, soc_mmu_h h2mmu)
{
	soc_mmu_p mmu;
	
	ERR_NULL(mmu = malloc(sizeof(soc_mmu_t)));
	if(!mmu)
		return(-1);
	
	memset(mmu, 0, sizeof(soc_mmu_t));
	
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

