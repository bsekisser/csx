static uint32_t _alubox_adc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn + rm + BEXT(CPSR, SOC_CORE_PSR_BIT_C));
}

static uint32_t _alubox_adcs(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_adc(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

static uint32_t _alubox_add(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn + rm);
}

static uint32_t _alubox_adds(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_add(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

static uint32_t _alubox_and(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn & rm);
}

static uint32_t _alubox_ands(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_and(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);
}

static uint32_t _alubox_bic(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn & ~rm);
}

static uint32_t _alubox_bics(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_bic(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);
}

static uint32_t _alubox_eor(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn ^ rm);
}

static uint32_t _alubox_eors(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_eor(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);
}

static uint32_t _alubox_mov(soc_core_p core, uint32_t rn, uint32_t rm) {
	assert(0 == rR(N));

	rR(N) = ~0;

	return(rm);
}

static uint32_t _alubox_movs(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_mov(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);
}

/*
	static uint32_t _alubox_mul(soc_core_p core, uint32_t rn, uint32_t rm) {
		return(rn * rm);
	}

	static uint32_t _alubox_muls(soc_core_p core, uint32_t rn, uint32_t rm) {
		uint32_t result = _alubox_mul(core, rn, rm);

		soc_core_flags_nz(core, result);

		return(result);
	}
*/

static uint32_t _alubox_mvn(soc_core_p core, uint32_t rn, uint32_t rm) {
	assert(0 == rR(N));

	rR(N) = ~0;

	return(~rm);
}

static uint32_t _alubox_mvns(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_mvn(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);
}

static uint32_t _alubox_orr(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn | rm);
}

static uint32_t _alubox_orrs(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_orr(core, rn, rm);

	if(CCx.e && (rPC != rR(D))) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);
}

static uint32_t _alubox_rsc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rm - (rn + BEXT(CPSR, SOC_CORE_PSR_BIT_C)));
}

static uint32_t _alubox_rscs(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_rsc(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

static uint32_t _alubox_rsb(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rm - rn);
}

static uint32_t _alubox_rsbs(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_rsb(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

static uint32_t _alubox_sbc(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn - (rm + BEXT(CPSR, SOC_CORE_PSR_BIT_C)));
}

static uint32_t _alubox_sbcs(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_sbc(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

static uint32_t _alubox_sub(soc_core_p core, uint32_t rn, uint32_t rm) {
	return(rn - rm);
}

static uint32_t _alubox_subs(soc_core_p core, uint32_t rn, uint32_t rm) {
	uint32_t result = _alubox_sub(core, rn, rm);
	
	if(CCx.e && (rPC != rR(D)))
		soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

/* **** */

static uint32_t _alubox_cmns(soc_core_p core, uint32_t rn, uint32_t rm) {
	assert(0 == rR(D));

	uint32_t result = _alubox_add(core, rn, rm);
	
	if(CCx.e)
		soc_core_flags_nzcv_add(core, result, rn, rm);

	return(result);
}

static uint32_t _alubox_cmps(soc_core_p core, uint32_t rn, uint32_t rm) {
	assert(0 == rR(D));

	uint32_t result = _alubox_sub(core, rn, rm);
	
	if(CCx.e)
		soc_core_flags_nzcv_sub(core, result, rn, rm);

	return(result);
}

static uint32_t _alubox_teqs(soc_core_p core, uint32_t rn, uint32_t rm) {
	assert(0 == rR(D));

	uint32_t result = _alubox_eor(core, rn, rm);

	if(CCx.e) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);
}

static uint32_t _alubox_tsts(soc_core_p core, uint32_t rn, uint32_t rm) {
	assert(0 == rR(D));

	uint32_t result = _alubox_and(core, rn, rm);

	if(CCx.e) {
		soc_core_flags_nz(core, result);
		BMAS(CPSR, SOC_CORE_PSR_BIT_C, vR(SOP_C));
	}

	return(result);
}
