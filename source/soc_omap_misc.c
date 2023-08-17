#include "soc_omap_misc.h"

/* **** */

#include "csx_mmio.h"
#include "csx_data.h"
#include "csx.h"

/* **** */

#include "callback_qlist.h"
#include "err_test.h"
#include "handle.h"
#include "log.h"

/* **** */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/* **** */

typedef struct soc_omap_misc_t {
	csx_p csx;
	csx_mmio_p mmio;
	
	struct {
		unsigned syss;
	}i2c;

	uint8_t sossi[0x100];
	uint8_t spi[0x100];
	uint8_t x_fe_60[0x100];
	uint8_t x_fe_68[0x100];
	uint8_t x_fe_78[0x100];

	callback_qlist_elem_t atexit;
}soc_omap_misc_t;

/* **** */

static int __soc_omap_misc_atexit(void* param)
{
	if(_trace_atexit)
		LOG();
	
	handle_free(param);
	return(0);
}

/* **** */

static uint32_t _soc_omap_misc_fe_60_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;
	
	csx_data_target_t target = {
		.base = misc->x_fe_60,
		.offset = ppa & 0xff,
		.size = sizeof(uint32_t),
	};
	
	uint32_t data = csx_data_target_mem_access(&target, size, write);

	switch(ppa) {
		case 0xfffe6014:
		case 0xfffe6018:
			data |= 1;
	}

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

static uint32_t _soc_omap_misc_fe_68_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;
	
	csx_data_target_t target = {
		.base = misc->x_fe_68,
		.offset = ppa & 0xff,
		.size = sizeof(uint32_t),
	};
	
	uint32_t data = csx_data_target_mem_access(&target, size, write);
	unsigned rmw = 0;

	switch(ppa) {
		case 0xfffe6838:
			if(!write) {
				rmw = 1;
				data ^= _BV(15);
			}
			break;
	}

	if(rmw)
		csx_data_target_mem_access(&target, size, &data);

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

static uint32_t _soc_omap_misc_fe_78_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;
	
	csx_data_target_t target = {
		.base = misc->x_fe_78,
		.offset = ppa & 0xff,
		.size = sizeof(uint32_t),
	};
	
	uint32_t data = csx_data_target_mem_access(&target, size, write);

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static uint32_t _soc_omap_misc_i2c_sysc(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;

	const unsigned data = write ? *write : 0;
	if(write && BEXT(data, 1))
		misc->i2c.syss |= 1;

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

static uint32_t _soc_omap_misc_i2c_syss(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;

	const unsigned data = misc->i2c.syss;
	if(!write)
		misc->i2c.syss = 0;

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static uint32_t _soc_omap_misc_sossi_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;
	
	csx_data_target_t target = {
		.base = misc->sossi,
		.offset = ppa & 0xff,
		.size = sizeof(uint16_t),
	};
	
	uint32_t data = csx_data_target_mem_access(&target, size, write);

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

static uint32_t _soc_omap_misc_spi_mem_access(void* param, uint32_t ppa, size_t size, uint32_t* write)
{
	const soc_omap_misc_p misc = param;
	const csx_p csx = misc->csx;
	
	csx_data_target_t target = {
		.base = misc->spi,
		.offset = ppa & 0xff,
		.size = sizeof(uint16_t),
	};
	
	uint32_t data = csx_data_target_mem_access(&target, size, write);

	switch(ppa) {
		case 0xfffb0c14:
			data |= 1;
			break;
	}

	if(_trace_mmio_misc)
		CSX_MMIO_TRACE_MEM_ACCESS(csx, ppa, size, write, data);

	return(data);
}

/* **** */

static csx_mmio_access_list_t __soc_omap_misc_acl[] = {
	MMIO_TRACE_FN(0xfffb, 0x0c14, 0x0000, 0x0000, spi1_ssr, _soc_omap_misc_spi_mem_access)
//	
	MMIO_TRACE_FN(0xfffb, 0x3810, 0x0000, 0x0000, xfffb_3810, _soc_omap_misc_i2c_syss)
	MMIO_TRACE_FN(0xfffb, 0x3820, 0x0000, 0x0000, xfffb_3810, _soc_omap_misc_i2c_sysc)
//
	MMIO_TRACE_FN(0xfffb, 0xac00, 0x0000, 0x0000, xfffb_ac00, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac04, 0x0000, 0x0000, xfffb_ac04, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac08, 0x0000, 0x0000, xfffb_ac08, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac0c, 0x0000, 0x0000, xfffb_ac0c, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac10, 0x0000, 0x0000, xfffb_ac10, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac14, 0x0000, 0x0000, xfffb_ac14, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac18, 0x0000, 0x0000, xfffb_ac18, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac1c, 0x0000, 0x0000, xfffb_ac1c, _soc_omap_misc_sossi_mem_access)
	MMIO_TRACE_FN(0xfffb, 0xac20, 0x0000, 0x0000, xfffb_ac20, _soc_omap_misc_sossi_mem_access)
//
	MMIO_TRACE_FN(0xfffe, 0x6010, 0x0000, 0x0000, xfffe_6010, _soc_omap_misc_fe_60_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6014, 0x0000, 0x0000, xfffe_6014, _soc_omap_misc_fe_60_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6018, 0x0000, 0x0000, xfffe_6018, _soc_omap_misc_fe_60_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x601c, 0x0000, 0x0000, xfffe_601c, _soc_omap_misc_fe_60_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6020, 0x0000, 0x0000, xfffe_6020, _soc_omap_misc_fe_60_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6030, 0x0000, 0x0000, xfffe_6030, _soc_omap_misc_fe_60_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x6034, 0x0000, 0x0000, xfffe_6043, _soc_omap_misc_fe_60_mem_access)
//
	MMIO_TRACE_FN(0xfffe, 0x6838, 0x0000, 0x0000, xfffe_6838, _soc_omap_misc_fe_68_mem_access)
//
	MMIO_TRACE_FN(0xfffe, 0x7800, 0x0000, 0x0000, xfffe_7800, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7802, 0x0000, 0x0000, xfffe_7802, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7804, 0x0000, 0x0000, xfffe_7804, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7806, 0x0000, 0x0000, xfffe_7806, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7808, 0x0000, 0x0000, xfffe_7808, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x780a, 0x0000, 0x0000, xfffe_780a, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x780c, 0x0000, 0x0000, xfffe_780c, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x780e, 0x0000, 0x0000, xfffe_780e, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7810, 0x0000, 0x0000, xfffe_7810, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7812, 0x0000, 0x0000, xfffe_7812, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7814, 0x0000, 0x0000, xfffe_7814, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7816, 0x0000, 0x0000, xfffe_7816, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x7818, 0x0000, 0x0000, xfffe_7818, _soc_omap_misc_fe_78_mem_access)
	MMIO_TRACE_FN(0xfffe, 0x781a, 0x0000, 0x0000, xfffe_781a, _soc_omap_misc_fe_78_mem_access)

	{ .ppa = ~0U, },
};

soc_omap_misc_p soc_omap_misc_alloc(csx_p csx, csx_mmio_p mmio, soc_omap_misc_h h2misc)
{
	ERR_NULL(csx);
	ERR_NULL(mmio);
	ERR_NULL(h2misc);
	
	if(_trace_alloc) {
		LOG();
	}

	/* **** */

	soc_omap_misc_p misc = handle_calloc((void**)h2misc, 1, sizeof(soc_omap_misc_t));
	ERR_NULL(misc);
	
	misc->csx = csx;
	misc->mmio = mmio;

	/* **** */

	csx_mmio_callback_atexit(mmio, &misc->atexit, __soc_omap_misc_atexit, h2misc);

	/* **** */
	
	return(misc);
}

void soc_omap_misc_init(soc_omap_misc_p misc)
{
	ERR_NULL(misc);
	
	if(_trace_init) {
		LOG();
	}

	/* **** */

	csx_mmio_register_access_list(misc->mmio, 0, __soc_omap_misc_acl, misc);
}
