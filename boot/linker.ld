MEMORY
{
	ROM0(rx) :
		ORIGIN = 0x00000000, LENGTH = 64K
	ROM1(rx) :
		ORIGIN = 0x00010000, LENGTH = 192K
	SDRAM(wx) :
		ORIGIN = 0x10000000, LENGTH = 64M
	SRAM(wx) :
		ORIGIN = 0x20000000, LENGTH = 250K - STACK_SPACE
	MMIO(rw) :
		ORIGIN = 0xfffe0000, LENGTH = 16M
}

SECTIONS
{
	STACK_SPACE = 2K;

	.text :
	{
		KEEP(*(.text.ivt))
		*(.text*)

		KEEP(*(.init))
		KEEP(*(.fini))

		*(.rodata*)

		__text_end = .;
	} > ROM0

	.text :
	{
		*(.glue_7*)
		*(.glue_7t*)
		*(.vfp11_veneer*)
		*(.v4_bx*)
		*(.iplt*)
		*(.rel.dyn*)
		*(.rel.iplt*)
		*(.igot.plt*)
		*(.tm_clone_table*)

		*(.text*)
		*(.rodata*)

		*(.eh_frame*)
	} > ROM1

	.copy.table :
	{
		. = ALIGN(4);
		PROVIDE_HIDDEN(__copy_table_start = .);
			LONG(__data_start_lma);
			LONG(__data_start);
			LONG(__data_end - __data_start);
		PROVIDE_HIDDEN(__copy_table_end = .);
	} > ROM0

	.zero.table :
	{
		. = ALIGN(4);
		PROVIDE_HIDDEN(__zero_table_start = .);
			LONG(__bss_start);
			LONG(__bss_end - __bss_start);
		PROVIDE_HIDDEN(__zero_table_end = .);
	} > ROM0
	
	.fill0 :
	{
		FILL(0);
		. = ORIGIN(ROM0) + LENGTH(ROM0) - 1;
		BYTE(0);
	} > ROM0

	.fill1 :
	{
		FILL(0);
		. = ORIGIN(ROM1) + LENGTH(ROM1) - 1 - (__data_end - __data_start);
		BYTE(0);
	} > ROM1

	__data_start_lma = ALIGN(4);
	.data : AT(__data_start_lma)
	{
		__data_start = .;
		*(.vtable)
		*(.data*)

		. = ALIGN(4);
		PROVIDE_HIDDEN(*__preinit_array_start = .);
		KEEP(*(.preinit_array));
		PROVIDE_HIDDEN(*__preinit_array_end = .);

		. = ALIGN(4);
		PROVIDE_HIDDEN(*__init_array_start = .);
		KEEP(*(SORT(.init_array.*)));
		KEEP(*(.init_array));
		PROVIDE_HIDDEN(*__init_array_end = .);

		. = ALIGN(4);
		PROVIDE_HIDDEN(*__fini_array_start = .);
		KEEP(*(SORT(.fini_array.*)));
		KEEP(*(.fini_array));
		PROVIDE_HIDDEN(*__fini_array_end = .);

		. = ALIGN(4);
		__data_end = .;
	} > SRAM

	.bss (NOLOAD) :
	{
		. = ALIGN(4);
		__bss_start = .;
		*(.bss*)
		*(COMMON)
		. = ALIGN(4);
		__bss_end = .;
	} > SRAM

	.heap (COPY) :
	{
		__heap_start = .;
		*(.heap*)
		__heap_end = ORIGIN(SRAM) + LENGTH(SRAM);
	} > SRAM

	.stack (COPY) :
	{
		*(.stack*)
	} > SRAM

	__stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
