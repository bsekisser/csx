MEMORY
{
	ROM0(rx) :
		ORIGIN = 0x00000000, LENGTH = 64K
	ROM1(rx) :
		ORIGIN = 0x00010000, LENGTH = 192K
	SDRAM(wx) :
		ORIGIN = 0x10000000, LENGTH = 64M
	SRAM(wx) :
		ORIGIN = 0x20000000, LENGTH = 250K
#	CIF1(wx) :
#		ORIGIN = 0x2007d800, LENGTH = 2K
#	CIF2(wx) :
#		ORIGIN = 0x3007d800, LENGTH = 2K
#	DSP(wx) :
#		ORIGIN = 0xe0000000, LENGTH = 260K
#	MMIO(rw) :
#		ORIGIN = 0xfffb0000, LENGTH = 256K
}

SECTIONS
{
	SRAM_IVT_SPACE = 1K;
	STACK_SPACE = 2K;

	.text :
	{
		FILL(0);
		KEEP(*(.text.ivt))
		*(.text*)

		KEEP(*(.init))
		KEEP(*(.fini))

		*(.rodata*)

		PROVIDE_HIDDEN(__text_end = .);
		BYTE(0);
	} > ROM0

	.text :
	{
		FILL(0);
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
		. = ORIGIN(ROM1) + LENGTH(ROM1) - 1;
		BYTE(0);
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
	
	PROVIDE_HIDDEN(__data_start_lma = .);
	
	.ram_ivt (NOLOAD) :
	{
		. = ORIGIN(SRAM);
		__ram_ivt_start = .;
		. += SRAM_IVT_SPACE;
		__ram_ivt_end = .;
	} > SRAM
	
	.data : AT(__data_start_lma)
	{
		PROVIDE_HIDDEN(__data_start = .);
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
		PROVIDE_HIDDEN(__data_end = .);
	} > SRAM

	.bss (NOLOAD) :
	{
		. = ALIGN(4);
		PROVIDE_HIDDEN(__bss_start = .);
		*(.bss*)
		*(COMMON)
		. = ALIGN(4);
		PROVIDE_HIDDEN(__bss_end = .);
	} > SRAM

	.heap (COPY) :
	{
		PROVIDE_HIDDEN(__heap_start = .);
		*(.heap*)
		. = ORIGIN(SRAM) + LENGTH(SRAM) - STACK_SPACE;
		PROVIDE_HIDDEN(__heap_end = .);
	} > SRAM

	.stack (COPY) :
	{
		. = ALIGN(16);
#		PROVIDE_HIDDEN(__stack_bottom = __stack_top - STACK_SIZE);
		*(.stack*)
		. = ALIGN(16);
		PROVIDE_HIDDEN(__stack_top = ORIGIN(SRAM) + LENGTH(SRAM));
	} > SRAM
}
