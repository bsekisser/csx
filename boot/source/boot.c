#include <crt.h>
#include <stdint.h>
#include <string.h>

/* **** */

int main(void);

extern char __copy_table_end, __copy_table_start;
extern char __zero_table_end, __zero_table_start;

/* **** */

#if 0
	extern inline
	void __bkpt() { asm("bkpt") ; }
#endif

extern inline __attribute__((noreturn))
void __hang() { while(1) ; }

extern inline __attribute__((noreturn))
void __halt() { asm("hlt"); __hang(); }

__attribute__((weak, alias("__halt"))) void exception_data_abort(void);
__attribute__((weak, alias("__halt"))) void exception_fiq(void);
__attribute__((weak, alias("__halt"))) void exception_irq(void);
__attribute__((weak, alias("__halt"))) void exception_prefetch_abort(void);
__attribute__((weak, alias("__halt"))) void exception_undefined(void);
__attribute__((weak, alias("__halt"))) void exception_swi(void);
__attribute__((weak, alias("__halt"))) void vector_reserved(void);

//__attribute__((naked, noreturn))
void reset_handler(void)
{
	zero_table_ptr zt = (void*)&__zero_table_start;
		void* end = &__zero_table_end;
	for(; (void*)zt < end; zt++)
		memset(zt->start, 0, zt->bytes);

	copy_table_ptr ct = (void*)&__copy_table_start;
		end = &__copy_table_end;
	for(; (void*)ct < end; ct++)
		memcpy(ct->start, ct->lma, ct->bytes);

/* **** */

	_preinit();
	_init();

/* **** */

	(void)main();

/* **** */

	_fini();
	__halt();
}
