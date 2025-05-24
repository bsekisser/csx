#pragma once

/* **** */

typedef struct csx_cache_tag** csx_cache_hptr;
typedef csx_cache_hptr const csx_cache_href;

typedef struct csx_cache_tag* csx_cache_ptr;
typedef csx_cache_ptr const csx_cache_ref;

/* **** */

#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

extern action_list_t csx_cache_action_list;

csx_cache_ptr csx_cache_alloc(csx_ref csx, csx_cache_href h2cache);
