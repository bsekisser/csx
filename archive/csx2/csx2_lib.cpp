#include <stdint.h>
#include <stdio.h>

#include "../../../include/err_test.h"

enum {
	csx_cc_flag_v,
	csx_cc_flag_c,
	csx_cc_flag_z,
	csx_cc_flag_n,
};

#define csx_cc_eq 0
#define csx_cc_lo 0
#define csx_cc_ne 0

#define APSR 0
#define CPSR_C 0

#define FP _r(11)
#define IP _r(12)
#define SP _r(13)
#define LR _r(14)
#define PC _r(15)

typedef uint8_t reg_t;

#define _c(_x) ((reg_t)((1 << 4) | (_x & 0x0f)))
#define _r(_x) ((reg_t)((0 << 4) | (_x & 0x0f)))
#define _p(_x) ((reg_t)((2 << 4) | (_x & 0x0f)))

typedef struct csx_t* csx_p;
typedef struct csx_t {
	uint32_t	c[16];
	uint32_t	r[16];
	uint32_t	p[16];
	void*		data;
}csx_t;

static csx_t ccsx, *csx = &ccsx;

/* ??? */
#define SB 0
#define SL 0

/* **** */

#define LSL(_v) _v
#define LSR(_v) (-(_v))

/* **** */

static uint32_t csx_mmu_read(csx_p csx, uint32_t ea, uint8_t size)
{
	LOG("ea = 0x%08x, size = 0x%hhx", ea, size);
	return(0);
}

static void csx_mmu_write(csx_p csx, uint32_t ea, uint32_t v, uint8_t size)
{
	LOG("ea = 0x%08x, size = 0x%hhx, v = 0x%08x", ea, size, v);
}

static uint32_t csx_reg_get(csx_p csx, reg_t rs)
{
	return(csx->r[rs]);
}

static void csx_reg_set(csx_p csx, reg_t rd, uint32_t v)
{
	csx->r[rd] = v;
}

#define csx_update_flags(...)

/* **** */

#define ALU_r_r_v(_name, _op) \
	static void _name(reg_t rd, reg_t rs, int v) \
	{ \
		uint32_t res = csx_reg_get(csx, rs) _op v; \
		csx_reg_set(csx, rd, res); \
	}

#define ALU_r_r_r_s(_name, _op) \
	static void _name(reg_t rd, reg_t rs1, reg_t rs2, int8_t shift = 0) \
	{ \
		uint32_t rs1v = csx_reg_get(csx, rs1); \
		uint32_t rs2v = csx_reg_get(csx, rs2); \
		uint32_t res = rs1v _op (rs2v << shift); \
		csx_reg_set(csx, rd, res); \
	}

#define ALUs_r_r_r_s(_name, _op) \
	static void _name(reg_t rd, reg_t rs1, reg_t rs2, int8_t shift = 0) \
	{ \
		uint32_t rs1v = csx_reg_get(csx, rs1); \
		uint32_t rs2v = csx_reg_get(csx, rs2); \
		uint32_t res = rs1v _op (rs2v << shift); \
		csx_reg_set(csx, rd, res); \
		csx_update_flags(csx, res); \
	}

#define ALUs_r_r_v_s(_name, _op) \
	static void _name(reg_t rd, reg_t rs1, int v, int8_t shift = 0) \
	{ \
		uint32_t rs1v = csx_reg_get(csx, rs1); \
		uint32_t res = rs1v _op (v << shift); \
		csx_reg_set(csx, rd, res); \
		csx_update_flags(csx, res); \
	}


ALU_r_r_v(add, +)
ALU_r_r_r_s(aand, &)
ALUs_r_r_r_s(ands, &)

static void b(uint32_t addr)
{
	uint32_t pcv = csx_reg_get(csx, PC);
	uint32_t new_pc = pcv + addr;

	LOG("addr = 0x%08x[0x%08x] -- > 0x%08x", pcv, addr, new_pc);

	csx_reg_set(csx, PC, new_pc);
}

#define bx(_ea)

#define bic(...)

#define cmp(...)
#define cmpeq(...)

#if 0
static void ldr(reg_t rd, reg_t rs)
{
	uint32_t ea = csx_reg_get(csx, rs);
	uint32_t eav = csx_mmu_read(csx, ea);
	csx_reg_set(csx, rd, eav);
}
#endif

static void ldr(reg_t rd, reg_t rs, uint16_t offset = 0)
{
	uint32_t ea = csx_reg_get(csx, rs) + offset;
	uint32_t eav = csx_mmu_read(csx, ea, sizeof(uint32_t));
	csx_reg_set(csx, rd, eav);
}

static void ldrh(reg_t rd, reg_t rs)
{
	uint32_t ea = csx_reg_get(csx, rs);
	uint32_t eav = csx_mmu_read(csx, ea, sizeof(uint16_t));
	csx_reg_set(csx, rd, eav);
}

#define mcr(...)

#if 0
static void mov(reg_t rd, int v)
{
	csx_reg_set(csx, rd, v);
}
#endif

static void mov(reg_t rd, int v, int8_t shift = 0)
{
	uint32_t res = v << shift;
	csx_reg_set(csx, rd, v << shift);
}

static void mov(reg_t rd, reg_t rs, int8_t shift = 0)
{
	uint32_t rsv = csx_reg_get(csx, rs);
	uint32_t res = rsv << shift;
	csx_reg_set(csx, rd, res);
}

#define mrs(...)
#define msr(...)
#define mvn(...)

ALU_r_r_v(orr, |)
ALU_r_r_r_s(orr, |)

#define stc2l(...)

#if 0
static void str(reg_t rs, reg_t rd)
{
	uint32_t ea = csx_reg_get(csx, rd);
	csx_mmu_write(csx, ea, csx_reg_get(csx, rs));
}
#endif

static void str(reg_t rs, reg_t rd, uint16_t offset = 0)
{
	uint32_t ea = csx_reg_get(csx, rd) + offset;
	uint32_t eav = csx_reg_get(csx, rs);
	csx_mmu_write(csx, ea, eav, sizeof(uint32_t));
}

static void strh(reg_t rs, reg_t rd)
{

	uint32_t ea = csx_reg_get(csx, rd);
	uint32_t eav = csx_reg_get(csx, rs);
	csx_mmu_write(csx, ea, eav, sizeof(uint16_t));
}

ALU_r_r_r_s(sub, -)
ALUs_r_r_v_s(subs, -)

#define I(_addr, _cc_flags, args...) \
	x##_addr: \
		if(_addr == csx_reg_get(csx, PC))
		{ \
			args; \
		}

#define INVALID(_addr)

#define LBRAC
#define LBRACE

#define RBRAC
#define RBRACE

#define WRITE_BACK

extern "C" void csx2(void *data);
void csx2(void *data)
{
	#include "../../csx1.out"
}
