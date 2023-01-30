#pragma once

/* **** */

#include "cracker_arm_enum.h"

/* **** */

#include <stdint.h>

/* **** */

#define ALU_BOX_LIST(_ESAC) \
	_ESAC(ARM_ADD, s1 + s2) \
	_ESAC(ARM_AND, s1 & s2) \
	_ESAC(ARM_BIC, s1 & ~s2) \
	_ESAC(ARM_EOR, s1 ^ s2) \
	_ESAC(ARM_MOV, s2) \
	_ESAC(ARM_MVN, -s2) \
	_ESAC(ARM_ORR, s1 | s2) \
	_ESAC(ARM_RSB, s2 - s1) \
	_ESAC(ARM_SUB, s1 - s2) \

/* **** */

#if 0
	#define ENUM(_esac, _action) \
		_esac,

	enum {
		ALU_BOX_LIST(ENUM)
	};

	#undef ENUM
#endif

/* **** */

static inline uint32_t alubox(uint8_t op, uint32_t s1, uint32_t s2)
{
#define SWITCH_CASE(_esac, _action) \
	case _esac: \
		return(_action);

	switch(op) {
		ALU_BOX_LIST(SWITCH_CASE)
		default:
			LOG_ACTION(exit(-1));
	}

	return(0);
}

#undef SWITCH_CASE

/* **** */

#undef ALU_BOX_LIST
