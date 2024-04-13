#pragma once

/* **** */

//#include "soc_core.h"

/* **** */

//typedef void (*alubox_fn)(soc_core_p core, uint32_t* wb);

enum {
	__alubox_shift_lsl,
	__alubox_shift_lsr,
	__alubox_shift_asr,
	__alubox_shift_ror,
	__alubox_shift_rrx,
};

/* **** */

#ifndef __ALUBOX_INLINE__
	#define __ALUBOX_INLINE__ inline
#endif

#ifndef __ALUBOX_STATIC__
	#define __ALUBOX_STATIC__ static
#endif
