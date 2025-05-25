#pragma once

/* **** */

#include <stddef.h>
#include <types.h>

/* **** */

void* memcpy(void *const dst, const void *const src, const size_t n);
void* mempcpy(void *const dst, const void *const src, const size_t n);
void* memset(void *const dst, const int c, const size_t n);
char* stpcpy(char *const dst, const char *const src);
char* strcpy(char *const dst, const char *const src);
size_t strlen(const char *const src);
