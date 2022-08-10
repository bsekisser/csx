#pragma once

#define _setup_rR_vR(_rvx, _rr, _vr) \
	({ \
		rR(_rvx) = _rr; \
		vR(_rvx) = _vr; \
	})

static inline void csx_core_decode_get(csx_core_p core,
	uint _rxx,
	uint msb,
	uint lsb,
	int get_rxx)
{
	csx_reg_p p2r = &rRX(_rxx);

	*p2r = mlBFEXT(IR, msb, lsb);
	
	if(get_rxx)
		vRX(_rxx) = csx_reg_get(core, *p2r);
}
