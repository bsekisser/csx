#pragma once

/* **** */

#include <stdint.h>

/* **** */

static inline
uint32_t _band(const uint32_t v, const uint8_t bit)
{ return(v & (1 << bit)); }

static inline
void band(uint32_t *const v, const uint8_t bit)
{ *v = _band(*v, bit); }

static inline
uint32_t _bclr(const uint32_t v, const uint8_t bit)
{ return(v & ~(1 << bit)); }

static inline
void bclr(uint32_t *const v, const uint8_t bit)
{ *v = _bclr(*v, bit); }

static inline
uint32_t _beor(const uint32_t v, const uint8_t bit)
{ return(v ^ (1 << bit)); }

static inline
void beor(uint32_t *const v, const uint8_t bit)
{ *v = _beor(*v, bit); }

static inline
uint32_t _bext(const uint32_t v, const uint8_t bit)
{ return((v >> bit) & 1); }

static inline
void bext(uint32_t *const v, const uint8_t bit)
{ *v = _bext(*v, bit); }

static inline
uint32_t _borr(const uint32_t v, const uint8_t bit)
{ return(v | (1 << bit)); }

static inline
void borr(uint32_t *const v, const uint8_t bit)
{ *v = _borr(*v, bit); }

static inline
uint32_t _bset(const uint32_t v, const uint8_t bit)
{ return(v | (1 << bit)); }

static inline
void bset(uint32_t *const v, const uint8_t bit)
{ *v = _bset(*v, bit); }
