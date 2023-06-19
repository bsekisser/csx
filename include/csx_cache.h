#pragma once

/* **** */

typedef struct csx_cache_t** csx_cache_h;
typedef struct csx_cache_t* csx_cache_p;

/* **** */

#include "csx.h"

/* **** */

csx_cache_p csx_cache_alloc(csx_p csx, csx_cache_h h2cache);
void csx_cache_init(csx_cache_p cache);
