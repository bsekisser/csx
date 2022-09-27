#include <stdint.h>

typedef uint32_t pc_t;
typedef pc_t* pc_t_p;

typedef uint32_t sp_t;
typedef sp_t* sp_t_p;

typedef void (*void_fn_t)(void);

enum {
/*		a1..a4 -- r0..r3
	v1..v8 -- r4..r11
*/		rSB = 9,
	rSL = 10,
	rFP = 11,
	rIP = 12, /* intra-procedure call */
	rSP = 13,
	rLR = 14,
	rPC = 15,
};

register uint32_t R0 asm("r0");
#define R(_x) R##_x

register pc_t IR asm("r7");
register pc_t_p PC asm("r8");
register pc_t_p IP asm("r9");
register sp_t_p SP asm("r13");

/* **** */

#define IR_ARG24s (((signed int)IR) >> 8)
#define IR_ARG24u (((unsigned int)IR) >> 8)

/*static inline pc_t IR_ARG24s(void) {
	return(((signed int)IR) >> 8);
}*/

/* **** */

#define DO_CALL(_x) \
	({ \
		void_fn_t fn = (void*)_x; \
		fn(); \
	})

/* **** */

#define INST_ESAC_LIST \
	INST_ESAC(nop, ;) \
	INST_ESAC(call, DO_CALL(R(0))) \
	INST_ESAC(lis, R(0) = IR_ARG24s) \
	INST_ESAC(liu, R(0) = IR_ARG24u) \
	INST_ESAC(ori, R(0) |= IR_ARG24u) \
	INST_ESAC(r0_to_pc, PC = (pc_t_p)R(0)) \
	INST_ESAC(r0_to_sp, SP = (sp_t_p)R(0)) \

/* **** */

#define INST_ESAC(_esac, _action) \
	_esac,

enum {
	INST_ESAC_LIST
	INST_ESAC_COUNT
};

#undef INST_ESAC

/* **** */

#define INST_ESAC(_esac, _action) \
	static void tfvm_inst_##_esac(void) { \
		_action; \
	}

INST_ESAC_LIST

#undef INST_ESAC

/* **** */

#define INST_ESAC(_esac, _action) \
	tfvm_inst_##_esac,

void_fn_t vm_fn_list[INST_ESAC_COUNT] = {
	INST_ESAC_LIST
};

#undef INST_ESAC

/* **** */

void tfvm_step(void) {
	IP = PC++;
	IR = *IP;
	
	return(vm_fn_list[IR]());
}

int main(void) {
	for(;;)
		tfvm_step();
}
