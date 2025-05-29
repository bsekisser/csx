#pragma once

/* **** */

typedef struct csx_nnd_tag** csx_nnd_hptr;
typedef csx_nnd_hptr const csx_nnd_href;

typedef struct csx_nnd_tag* csx_nnd_ptr;
typedef csx_nnd_ptr const csx_nnd_ref;

/* **** */

#include "csx.h"

/* **** */

#include "libbse/include/action.h"

/* **** */

extern action_list_t csx_nnd_flash_action_list;

csx_nnd_ptr csx_nnd_flash_alloc(csx_ref csx, csx_nnd_href nnd);

