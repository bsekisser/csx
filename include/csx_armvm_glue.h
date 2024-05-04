#pragma once

/* **** */

#include "csx.h"

/* **** */

//#include "libarmvm/include/armvm_glue.h"
//#include "libarmvm/include/armvm_core.h"
#include "libarmvm/include/armvm.h"

/* **** */

#include "libbse/include/bitfield.h"

/* **** */

#include <stdint.h>

/* **** */

#ifndef pARMVM_CORE
	#define pARMVM_CORE pARMVM->core
#endif

#ifndef pARMVM_MEM
	#define pARMVM_MEM pARMVM->mem
#endif

#ifndef CPSR
	#define CPSR armvm_spr32(pARMVM, ARMVM_SPR32(CPSR))
#endif

#ifndef IP
	#define IP armvm_spr32(pARMVM, ARMVM_SPR32(IP))
#endif

#ifndef IR
	#define IR armvm_spr32(pARMVM, ARMVM_SPR32(IR))
#endif

#ifndef PC
	#define PC armvm_gpr(pARMVM, ARMVM_GPR(PC), 0)
#endif

static inline int soc_core_in_a_privaleged_mode(csx_p const csx)
{ return(0 != mlBFEXT(CPSR, 3, 0)); }
