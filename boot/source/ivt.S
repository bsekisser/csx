.section .note.GNU-stack

.section .text.ivt

.globl _start
	b exception_reset
	b exception_undefined
	b exception_swi
	b exception_prefetch_abort
	b exception_data_abort
	b vector_reserved
	b exception_irq
	b exception_fiq

.extern reset_handler

exception_reset:
	ldr sp, =__stack_top
	bl reset_handler
