#pragma once

/* **** */

#include "soc_core_utility.h"

/* **** */

#include <stdint.h>

/* **** */

static void _soc_core_ldr_xxx(soc_core_p core,
	const uint before,
	const uint after,
	const uint8_t rdst)
{
	vR(N) += before;
	const uint32_t rxx_v = soc_core_read(core, vR(N), sizeof(uint32_t));
	soc_core_reg_set(core, rdst, rxx_v);
	vR(N) += after;
}

static void _soc_core_str_xxx(soc_core_p core,
	const uint before,
	const uint after,
	const uint8_t rsrc)
{
	vR(N) += before;
	const uint32_t rxx_v = soc_core_reg_get(core, rsrc);
	soc_core_write(core, vR(N), rxx_v, sizeof(uint32_t));
	vR(N) += after;
}

/* **** ldr */

__attribute__((unused))
static void _soc_core_ldrda(soc_core_p core, const uint8_t rs)
{
	_soc_core_ldr_xxx(core, 0, -sizeof(uint32_t), rs);
}

__attribute__((unused))
static void _soc_core_ldrdb(soc_core_p core, const uint8_t rs)
{
	_soc_core_ldr_xxx(core, -sizeof(uint32_t), 0, rs);
}

__attribute__((unused))
static void _soc_core_ldria(soc_core_p core, const uint8_t rs)
{
	_soc_core_ldr_xxx(core, 0, sizeof(uint32_t), rs);
}

__attribute__((unused))
static void _soc_core_ldrib(soc_core_p core, const uint8_t rs)
{
	_soc_core_ldr_xxx(core, sizeof(uint32_t), 0, rs);
}

/* **** str */

__attribute__((unused))
static void _soc_core_strda(soc_core_p core, const uint8_t rs)
{
	_soc_core_str_xxx(core, 0, -sizeof(uint32_t), rs);
}

__attribute__((unused))
static void _soc_core_strdb(soc_core_p core, const uint8_t rs)
{
	_soc_core_ldr_xxx(core, -sizeof(uint32_t), 0, rs);
}

__attribute__((unused))
static void _soc_core_stria(soc_core_p core, const uint8_t rs)
{
	_soc_core_str_xxx(core, 0, sizeof(uint32_t), rs);
}

__attribute__((unused))
static void _soc_core_strib(soc_core_p core, const uint8_t rs)
{
	_soc_core_str_xxx(core, sizeof(uint32_t), 0, rs);
}
