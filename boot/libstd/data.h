#pragma once

/* **** */

#include <stddef.h>
#include <types.h>

/* **** */

typedef union data_tag* data_ptr;
typedef data_ptr const data_ref;

typedef union data_tag {
	short *i16;
	long *i32;
	long long *i64;
	char i8;
	void *p;
	unsigned short *p2u16;
	unsigned long *p2u32;
	u32x4 *p2u32x4;
	u32x8 *p2u32x8;
	unsigned long long *p2u64;
	unsigned char *p2u8;
	u8x16 *p2u8x16;
	u8x32 *p2u8x32;
	unsigned short u16;
	unsigned long u32;
	u32x16 u32x16v;
	u32x4 u32x4v;
	u32x8 u32x8v;
	unsigned long long u64;
	unsigned char u8;
	u8x16 u8x16v;
	u8x32 u8x32v;
	u8x64 u8x64v;
}data_t;

/* **** */

static inline
void data_dst(data_ref dst, data_ref src, const size_t bytes)
{
	switch(bytes) {
		case 32: *dst->p2u8x32 = src->u8x32v; break;
		case 16: *dst->p2u8x16 = src->u8x16v; break;
		case 8: *dst->p2u64 = src->u64; break;
		case 4: *dst->p2u32 = src->u32; break;
		case 2: *dst->p2u16 = src->u16; break;
		case 1: *dst->p2u8 = src->u8; break;
	}
}

static inline
void* data_src(data_ref dst, data_ref src, const size_t bytes)
{
	switch(bytes) {
		case 32: dst->u8x32v = *src->p2u8x32; break;
		case 16: dst->u8x16v = *src->p2u8x16; break;
		case 8: dst->u64 = *src->p2u64; break;
		case 4: dst->u32 = *src->p2u32; break;
		case 2: dst->u16 = *src->p2u16; break;
		case 1: dst->u8 = *src->p2u8; break;
	}

	return(dst);
}
