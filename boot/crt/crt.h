#pragma once

/* **** */

extern void _fini(void);
extern void _init(void);
extern void _preinit(void);

/* **** */

typedef struct copy_table_tag* copy_table_ptr;
typedef copy_table_ptr const copy_table_ref;

typedef struct copy_table_tag {
	void* lma;
	void* start;
	long bytes;
}copy_table_t;

/* **** */

typedef struct zero_table_tag* zero_table_ptr;
typedef zero_table_ptr const zero_table_ref;

typedef struct zero_table_tag {
	void* start;
	long bytes;
}zero_table_t;
