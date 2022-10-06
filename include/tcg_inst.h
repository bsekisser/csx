/*
 * iuiu iuiu | iuiu iuiu | iuiu iuiu | opop opop
 * iuiu iuiu | iuiu iuiu | iuiu cccc | opop opop
 * iuiu iuiu | iuiu iuiu | r0r0 cccc | opop opop
 * iuiu iuiu | r2r2 r1r1 | r0r0 cccc | opop opop
 * s6s6 s6st | r2r2 r1r1 | r0r0 cccc | opop opop
 * 
 * cc -- condition
 * iu -- signed / unsigned value
 * r0 -- source / destination register
 * r1 -- base / source / target register
 * r2 -- source register
 * s6 -- 32 / 64 bit shift
 * st -- shift type
 *
 */

extern adc(tcg_p tcg, cc_t cc, reg_t r0, reg_t r1, reg_t r2, shift_t shift);
extern add(tcg_p tcg, cc_t cc, reg_t r0, reg_t r1, reg_t r2, shift_t shift);
extern and(tcg_p tcg, cc_t cc, reg_t r0, reg_t r1, reg_t r2, shift_t shift);
extern b(tcg_p tcg, int32_t offset);
extern bic(tcg_p tcg, cc_t cc, reg_t r0, reg_t r1, reg_t r2, shift_t shift);
extern bl(tcg_p tcg, int32_t offset);
extern blx(tcg_p tcg, int32_t offset);
extern eor(tcg_p tcg, cc_t cc, reg_t r0, reg_t r1, reg_t r2, shift_t shift);
extern mov(tcg_p tcg, cc_t cc, reg_t r0, reg_t r1, shift_t shift);
extern mvn(tcg_p tcg, cc_t cc, reg_t r0, reg_t r1, shift_t shift);
