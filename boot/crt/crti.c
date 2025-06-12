#include <crt.h>

/* **** */

typedef void (*func_ptr)(void);

/* **** */

extern func_ptr _fini_array_start[0], _fini_array_end[0];
extern func_ptr _init_array_start[0], _init_array_end[0];
extern func_ptr _preinit_array_start[0], _preinit_array_end[0];

/* **** */

static inline
void _process_list(void* start, void *end)
{
	for(func_ptr* func = start; func != end; func++)
		if(func) (*func)();
}

/* **** */

void _preinit(void)
{ return(_process_list(_preinit_array_start, _preinit_array_end)); }

void _init(void)
{ return(_process_list(_init_array_start, _init_array_end)); }

void _fini(void)
{ return(_process_list(_fini_array_start, _fini_array_end)); }

/* **** */

func_ptr _preinit_array_start[0] __attribute__((used, section(".preinit_array"),
aligned(sizeof(func_ptr)))) = {};

func_ptr _init_array_start[0] __attribute__((used, section(".init_array"),
aligned(sizeof(func_ptr)))) = {};

func_ptr _fini_array_start[0] __attribute__((used, section(".fini_array"),
aligned(sizeof(func_ptr)))) = {};
