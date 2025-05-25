#pragma once

/* **** */

static
void assert(const unsigned test)
{ if(!test) { asm("hlt"); while(1); } }
