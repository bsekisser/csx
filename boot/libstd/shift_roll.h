#pragma once

/* **** */

#include <stdint.h>

/* **** */

static inline
uint32_t _asr(const int32_t rm, const uint8_t rs)
{ return(rm >> rs); }

static inline
void asr(uint32_t *const rm, const uint8_t rs)
{ *rm = _asr(*rm, rs); }

static inline
uint32_t _lsl(const uint32_t rm, const uint8_t rs)
{ return(rm << rs); }

static inline
void lsl(uint32_t *const rm, const uint8_t rs)
{ *rm = _lsl(*rm, rs); }

static inline
uint32_t _lsl_masked(const uint32_t rm, const uint8_t rs)
{ return(_lsl(rm, rs & ((sizeof(rm) << 3) - 1))); }

static inline
uint32_t _lsr(const uint32_t rm, const uint8_t rs)
{ return(rm >> rs); }

static inline
void lsr(uint32_t *const rm, const uint8_t rs)
{ *rm = _lsr(*rm, rs); }

static inline
uint32_t _lsr_masked(const uint32_t rm, const uint8_t rs)
{ return(_lsr(rm, rs & ((sizeof(rm) << 3) - 1))); }

static inline
uint32_t _ror(const uint32_t rm, const uint8_t rs)
{ return(_lsl_masked(rm, -rs) | _lsr(rm, rs)); }

static inline
void ror(uint32_t *const rm, const uint8_t rs)
{ *rm = _ror(*rm, rs); }
