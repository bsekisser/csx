#pragma once

/* **** */

#include "soc_core.h"
#include "soc_core_reg.h"

/* **** */

#include "csx.h"

/* **** */

#include "libbse/include/bitfield.h"

/* **** */

#define _setup_rR_vR(_rvx, _rr, _vr) \
	({ \
		rR(_rvx) = _rr; \
		vR(_rvx) = _vr; \
	})

#define _setup_xR_xV(_xrv, _rr, _vr) \
	({ \
		rRX(_xrv) = _rr; \
		vRX(_xrv) = _vr; \
	})

static inline void _setup_rR_dst(soc_core_p core,
	const uint8_t rrx, const soc_core_reg_t rr)
{
	rRX(rrx) = rr;
}

static inline void _setup_rR_dst_rR_src(soc_core_p core,
	const uint8_t rrx, const soc_core_reg_t rrd, const uint8_t rrs)
{
	_setup_xR_xV(rrx, rrd, vRX(rrs));
}

static inline void _setup_rR_vR_src(soc_core_p core,
	const uint8_t rrx, const soc_core_reg_t rr)
{
#ifndef rRvRvPC
	#define rRvRvPC soc_core_reg_get(core, rPC)
//	#warning rRvRvPC undefined, using default
#endif

	if(rPC == rr) 
		_setup_xR_xV(rrx, rr, rRvRvPC);
	else
		_setup_xR_xV(rrx, rr, GPR(rr));
}

static inline soc_core_reg_t _soc_core_reg_decode(soc_core_p core,
	unsigned msb, unsigned lsb)
{
	return(mlBFEXT(IR, msb, lsb));
}

static inline void soc_core_decode_dst(soc_core_p core,
	unsigned rrx,
	unsigned msb,
	unsigned lsb)
{
	_setup_rR_dst(core, rrx, _soc_core_reg_decode(core, msb, lsb));
}

static inline void soc_core_decode_src(soc_core_p core,
	unsigned rrx,
	unsigned msb,
	unsigned lsb)
{
	_setup_rR_vR_src(core, rrx, _soc_core_reg_decode(core, msb, lsb));
}
