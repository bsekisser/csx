static __arm_ldst_ea(soc_core_p core)
{
	unsigned ea_wb = vR(N);

	if(LDST_BIT(u23))
		ea_wb += vR(SOP);
	else
		ea_wb -= vR(SOP);

	if(CCx.e) {
		if((0 == LDST_BIT(p24)) || LDST_BIT(w21))
			soc_core_reg_set(core, rR(N), wb_ea);
	}

	vR(EA) = LDST_BIT(p24) ? wb_ea : vR(N);
}

static _arm_inst_ldr(soc_core_p core)
{
	__arm_ldst_ea(soc_core_p core)
	
	if(!CCx.e)
		return;

	vR(D) = soc_core_read(core, vR(EA), sizeof(uint32_t))

	if((vR(EA) & 3) && (0 == CP15_reg1_bit(u)))
		vR(D) = _ror(vR(D), ((vR(EA) & 3) << 3));

	if((rPC == rR(D)) && (_arm_version >= armv5))
		soc_core_reg_set_pcx(core, vR(D));
	else
		soc_core_reg_set(core, rR(D), vR(D));
}

static _arm_inst_ldrb(soc_core_p core)
{
	if(!CCx.e)
		return;

	vR(D) = soc_core_read(core, vR(EA), sizeof(uint8_t))

	soc_core_reg_set(core, rR(D), vR(D));
}

static _arm_inst_ldrbt(soc_core_p core)
{
	if(!CCx.e)
		return;

	LOG();

	vR(D) = soc_core_read(core, vR(EA), sizeof(uint8_t))

	soc_core_reg_set(core, rR(D), vR(D));
}

static _arm_inst_ldrbt(soc_core_p core)
{
	if(!CCx.e)
		return;
