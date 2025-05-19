#pragma once

/* **** */

typedef struct csx_cache_tag** csx_cache_hptr;
typedef csx_cache_hptr const csx_cache_href;

typedef struct csx_cache_tag* csx_cache_ptr;
typedef csx_cache_ptr const csx_cache_ref;

/* **** */

#include "csx.h"

/* **** */

csx_cache_ptr csx_cache_alloc(csx_ref csx, csx_cache_href h2cache);
void csx_cache_init(csx_cache_ref cache);
