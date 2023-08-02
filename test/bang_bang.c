extern inline unsigned is_neg1(unsigned a) {
	return((a >> 31) & 1);
}

extern inline unsigned is_neg2(int a) {
	return(a < 0);
}

extern inline unsigned is_zero1(unsigned a) {
	return(0 == a);
}

extern inline unsigned is_zero2(unsigned a) {
	return(!(!!a));
}

/* **** */

typedef struct psr_t* psr_p;
typedef struct psr_t {
	unsigned result;

	union {
		unsigned raw_psr;
		struct {
			unsigned c:1;
			unsigned n:1;
			unsigned v:1;
			unsigned z:1;
		};
	};
}psr_t;


extern inline void _flags_nz1(psr_p psr, unsigned a) {
	psr->n = is_neg1(a);
	psr->z = is_zero1(a);

	psr->result = a;
}

extern inline void _flags_nz2(psr_p psr, unsigned a) {
	psr->n = is_neg2((signed)a);
	psr->z = is_zero2(a);

	psr->result = a;
}

extern inline unsigned _flags_add_cf(psr_p psr, unsigned a, unsigned b) {
	unsigned result = 0;

	psr->c = __builtin_uadd_overflow(a, b, &result);

	return(result);
}

extern inline unsigned _flags_add_cf2(psr_p psr, unsigned a, unsigned b) {
	unsigned result = a + b;

	psr->c = (result < a);

	return(result);
}

extern inline int _flags_add_vf(psr_p psr, int a, int b) {
	int result = 0;

	psr->v = __builtin_sadd_overflow(a, b, &result);

	return(result);
}

extern inline int _flags_add_vf2(psr_p psr, int a, int b) {
	int result = a + b;
	int stest = (a ^ result) & (b ^ result);

	psr->v = stest < 0;

	return(result);
}

extern inline unsigned _flags_add_cf_vf_1(psr_p psr, unsigned a, unsigned b) {
	unsigned result_c = 0;
	int result_v = 0;

	psr->c = __builtin_uadd_overflow(a, b, &result_c);

	const int aa = a;
	const int bb = b;

	psr->v = __builtin_sadd_overflow(aa, bb, &result_v);

	return(result_c);
}

extern inline unsigned _flags_add_cf_vf_2(psr_p psr, unsigned a, unsigned b) {
	unsigned result_c = _flags_add_cf(psr, a, b);

	const int aa = a;
	const int bb = b;

	int result_v = _flags_add_vf(psr, aa, bb);

	return(result_c);
}

extern inline unsigned _flags_add_cf_vf_3(psr_p psr, unsigned a, unsigned b) {
	unsigned result_c = 0;
	int result_v = 0;

	psr->c = __builtin_uadd_overflow(a, b, &result_c);
	psr->v = __builtin_sadd_overflow(a, b, &result_v);

	return(result_c);
}


extern inline unsigned _flags_add_cf_vf_4(psr_p psr, unsigned a, unsigned b) {
	unsigned result_c = _flags_add_cf(psr, a, b);
	int result_v = _flags_add_vf(psr, a, b);

	return(result_c);
}

extern inline unsigned _flags_add_cf_vf_5(psr_p psr, unsigned a, unsigned b) {
	unsigned result_c = 0;
	int result_v = 0;

	psr->c = __builtin_uadd_overflow(a, b, &result_c);
	psr->v = __builtin_add_overflow_p((signed)a, (signed)b, (a + b));

	return(result_c);
}

extern inline unsigned _flags_add_cf2_vf2(psr_p psr, unsigned a, unsigned b) {
	unsigned result_c = _flags_add_cf2(psr, a, b);
	_flags_add_vf2(psr, a, b);

	return(result_c);
}

extern inline unsigned _flags_add_cf2_vf2_nz2(psr_p psr, unsigned a, unsigned b) {
	unsigned result_c = _flags_add_cf2(psr, a, b);
	int result_v = _flags_add_vf2(psr, a, b);

	_flags_nz2(psr, result_c);

	return(result_c);
}

extern inline unsigned add_cf_nz1(psr_p psr, unsigned a, unsigned b) {
	unsigned result = _flags_add_cf(psr, a, b);

	_flags_nz1(psr, result);
	
	return(result);
}

extern inline unsigned add_cf_nz2(psr_p psr, unsigned a, unsigned b) {
	unsigned result = _flags_add_cf(psr, a, b);
	_flags_add_vf(psr, a, b);

	_flags_nz2(psr, result);
	
	return(result);
}

extern inline unsigned add_cf_vf_1(psr_p psr, unsigned a, unsigned b) {
	unsigned result = _flags_add_cf_vf_1(psr, a, b);

	_flags_nz2(psr, result);
	
	return(result);
}

extern inline unsigned add_cf_vf2_nz2(psr_p psr, unsigned a, unsigned b) {
	unsigned result = _flags_add_cf_vf_2(psr, a, b);

	_flags_nz2(psr, result);
	
	return(result);
}

extern inline unsigned _flags_sub_cf(psr_p psr, unsigned a, unsigned b) {
	unsigned result = 0;

	psr->c = __builtin_usub_overflow(a, b, &result);

	return(result);
}

extern inline int _flags_sub_vf(psr_p psr, int a, int b) {
	int result = 0;

	psr->v = __builtin_ssub_overflow(a, b, &result);

	return(result);
}

extern inline unsigned sub_cf_nz(psr_p psr, unsigned a, unsigned b) {
	unsigned result = _flags_sub_cf(psr, a, b);

	_flags_nz1(psr, result);
	
	return(result);
}

extern inline unsigned sub_cf_vf(psr_p psr, unsigned a, unsigned b) {
	unsigned result = _flags_sub_cf(psr, a, b);
	_flags_sub_vf(psr, a, b);

	_flags_nz2(psr, result);
	
	return(result);
}

#include <stdint.h>

extern inline uint64_t adc64u(uint64_t ir0, uint64_t ir1, uint64_t carry_in) {
	return(ir0 + ir1 + carry_in);
}

extern inline int64_t adc64s(int64_t ir0, int64_t ir1, uint64_t carry_in) {
	return(ir0 + ir1 + carry_in);
}

extern inline uint32_t add_with_carry(psr_p psr, uint32_t ir0, uint32_t ir1, uint32_t carry_in) {
	const uint64_t usum = adc64u(ir0, ir1, carry_in);
	const int64_t ssum = adc64s(ir0, ir1, carry_in);

//	const uint32_t result = (uint32_t)usum;
	const uint32_t result = ir0 + ir1 + carry_in;
//	const int32_t signed_result = (int32_t)usum;
	const int32_t signed_result = ((int32_t)ir0) + ((int32_t)ir1) + carry_in;

	_flags_nz1(psr, result);
	
	psr->c = !!(!(usum == result));
	psr->v = !!(!(ssum == signed_result));

	return(result);
}

extern inline unsigned do_add(psr_p psr, unsigned ir0, unsigned ir1, unsigned carry_in) {
	const unsigned result = ir0 + ir1 + carry_in;
	const unsigned xor = ir0 ^ ir1;

	psr->c = (ir0 & ir1) || (xor & !result);
	psr->v = !xor && (ir0 ^ result);
}
